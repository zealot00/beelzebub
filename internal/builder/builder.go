package builder

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"

	"github.com/beelzebub-labs/beelzebub/v3/internal/protocols/strategies/MCP"
	"github.com/beelzebub-labs/beelzebub/v3/internal/protocols/strategies/TELNET"

	"github.com/beelzebub-labs/beelzebub/v3/internal/evidence"
	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/internal/plugins"
	"github.com/beelzebub-labs/beelzebub/v3/internal/protocols"
	"github.com/beelzebub-labs/beelzebub/v3/internal/protocols/strategies/HTTP"
	"github.com/beelzebub-labs/beelzebub/v3/internal/protocols/strategies/SSH"
	"github.com/beelzebub-labs/beelzebub/v3/internal/protocols/strategies/TCP"
	"github.com/beelzebub-labs/beelzebub/v3/internal/tracer"
	"github.com/beelzebub-labs/beelzebub/v3/pkg/plugin"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	amqp "github.com/rabbitmq/amqp091-go"
	log "github.com/sirupsen/logrus"
)

const RabbitmqQueueName = "event"

type Builder struct {
	beelzebubServicesConfiguration []parser.BeelzebubServiceConfiguration
	beelzebubCoreConfigurations    *parser.BeelzebubCoreConfigurations
	traceStrategies                []tracer.Strategy
	rabbitMQChannel                *amqp.Channel
	rabbitMQConnection             *amqp.Connection
	syslogClient                   *syslogClient
	evidenceStore                  *evidence.Store
	logsFile                       *os.File
	startedServices                []plugin.ServicePlugin
	servicesCancel                 context.CancelFunc
	prometheusServer               *http.Server
}

// setTraceStrategies replaces the event sinks of the runtime.
func (b *Builder) setTraceStrategies(strategies []tracer.Strategy) {
	b.traceStrategies = strategies
}

// addTraceStrategy appends an event sink to the runtime.
//
// Sinks are independent: enabling several of them delivers every event to
// each of them instead of overriding the previously configured one.
func (b *Builder) addTraceStrategy(strategy tracer.Strategy) {
	b.traceStrategies = append(b.traceStrategies, strategy)
}

func (b *Builder) buildLogger(configurations parser.Logging) error {
	output := io.Writer(os.Stdout)

	if configurations.LogsPath != "" {
		// The log holds the credentials the attackers tried, and the payload
		// of the interactions: it must not be readable by the other local
		// users.
		logsFile, err := os.OpenFile(configurations.LogsPath, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return err
		}
		output = io.MultiWriter(os.Stdout, logsFile)
		b.logsFile = logsFile
	}

	log.SetOutput(output)

	log.SetFormatter(&log.JSONFormatter{
		DisableTimestamp: configurations.LogDisableTimestamp,
	})
	log.SetReportCaller(configurations.DebugReportCaller)
	if configurations.Debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	return nil
}

func (b *Builder) buildRabbitMQ(rabbitMQURI string) error {
	rabbitMQConnection, err := amqp.Dial(rabbitMQURI)
	if err != nil {
		return err
	}

	b.rabbitMQChannel, err = rabbitMQConnection.Channel()
	if err != nil {
		return err
	}

	//creates a queue if it doesn't already exist, or ensures that an existing queue matches the same parameters.
	if _, err = b.rabbitMQChannel.QueueDeclare(RabbitmqQueueName, false, false, false, false, nil); err != nil {
		return err
	}

	b.rabbitMQConnection = rabbitMQConnection
	return nil
}

// buildSyslog prepares the syslog pipeline. The connection itself is
// established lazily, so an unreachable log server never blocks the startup.
func (b *Builder) buildSyslog(conf parser.Syslog) error {
	client, err := newSyslogClient(conf)
	if err != nil {
		return err
	}

	b.syslogClient = client
	return nil
}

func (b *Builder) Close() error {
	if b.prometheusServer != nil {
		if err := b.prometheusServer.Close(); err != nil {
			return err
		}
	}

	// Stop background service plugins first so their goroutines drain before
	// other teardown.
	if b.servicesCancel != nil {
		b.servicesCancel()
	}
	for _, svc := range b.startedServices {
		svc.Stop()
	}

	// Close log file if it was opened
	if b.logsFile != nil {
		if err := b.logsFile.Close(); err != nil {
			return err
		}
	}

	// Close RabbitMQ connections
	if b.rabbitMQConnection != nil {
		if err := b.rabbitMQChannel.Close(); err != nil {
			return err
		}
		if err := b.rabbitMQConnection.Close(); err != nil {
			return err
		}
	}

	// Close the syslog connection
	if b.syslogClient != nil {
		if err := b.syslogClient.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (b *Builder) Run() error {
	fmt.Println(
		`
██████  ███████ ███████ ██      ███████ ███████ ██████  ██    ██ ██████  
██   ██ ██      ██      ██         ███  ██      ██   ██ ██    ██ ██   ██ 
██████  █████   █████   ██        ███   █████   ██████  ██    ██ ██████  
██   ██ ██      ██      ██       ███    ██      ██   ██ ██    ██ ██   ██ 
██████  ███████ ███████ ███████ ███████ ███████ ██████   ██████  ██████  
Deception runtime framework, happy hacking!`)
	if err := b.startPrometheus(); err != nil {
		return err
	}

	// Start registered background service plugins.
	svcCtx, cancel := context.WithCancel(context.Background())
	b.servicesCancel = cancel
	for _, svc := range plugin.Services() {
		if err := svc.Start(svcCtx); err != nil {
			log.Errorf("Error starting service plugin %q, continuing without it: %s",
				svc.Metadata().Name, err.Error())
			continue
		}
		b.startedServices = append(b.startedServices, svc)
	}

	// Init Protocol strategies
	secureShellStrategy := &SSH.SSHStrategy{}
	hypertextTransferProtocolStrategy := &HTTP.HTTPStrategy{}
	transmissionControlProtocolStrategy := &TCP.TCPStrategy{}
	modelContextProtocolStrategy := &MCP.MCPStrategy{}
	telnetStrategy := &TELNET.TelnetStrategy{}

	// Install the event sinks and publish the event bus to the plugin SDK,
	// so that plugins can observe every event from now on.
	tracerInstance := tracer.GetInstance(nil)
	tracerInstance.SetStrategies(b.traceStrategies)
	plugin.SetEventBus(tracerInstance)

	// The sample store observes every event to keep the payloads the
	// attackers drop on the decoys.
	if b.beelzebubCoreConfigurations.Core.Evidence.Enabled {
		store, err := evidence.NewStore(b.beelzebubCoreConfigurations.Core.Evidence)
		if err != nil {
			return err
		}
		b.evidenceStore = store
		tracerInstance.Subscribe(store.Handle)
	}

	// Init Tracer strategies, and set the trace strategy default HTTP
	var defaultStrategy tracer.Strategy
	if len(b.traceStrategies) > 0 {
		defaultStrategy = b.traceStrategies[0]
	}
	protocolManager := protocols.InitProtocolManager(defaultStrategy, hypertextTransferProtocolStrategy)

	if b.beelzebubCoreConfigurations.Core.BeelzebubCloud.Enabled {
		conf := b.beelzebubCoreConfigurations.Core.BeelzebubCloud

		beelzebubCloud := plugins.InitBeelzebubCloud(conf.URI, conf.AuthToken, true)

		if honeypotsConfiguration, _, err := beelzebubCloud.GetHoneypotsConfigurations(); err != nil {
			return err
		} else {
			if len(honeypotsConfiguration) == 0 {
				return errors.New("no honeypots configuration found")
			}
			b.beelzebubServicesConfiguration = honeypotsConfiguration
		}
	}

	for _, beelzebubServiceConfiguration := range b.beelzebubServicesConfiguration {
		switch beelzebubServiceConfiguration.Protocol {
		case "http":
			protocolManager.SetProtocolStrategy(hypertextTransferProtocolStrategy)
		case "ssh":
			protocolManager.SetProtocolStrategy(secureShellStrategy)
		case "tcp":
			protocolManager.SetProtocolStrategy(transmissionControlProtocolStrategy)
		case "mcp":
			protocolManager.SetProtocolStrategy(modelContextProtocolStrategy)
		case "telnet":
			protocolManager.SetProtocolStrategy(telnetStrategy)
		default:
			log.Fatalf("protocol %s not managed", beelzebubServiceConfiguration.Protocol)
		}

		if err := protocolManager.InitService(beelzebubServiceConfiguration); err != nil {
			return fmt.Errorf("error during init protocol: %s, %s", beelzebubServiceConfiguration.Protocol, err.Error())
		}
	}

	return nil
}

func (b *Builder) startPrometheus() error {
	config := b.beelzebubCoreConfigurations.Core.Prometheus
	if !config.Enabled {
		return nil
	}

	mux := http.NewServeMux()
	mux.Handle(config.Path, promhttp.Handler())
	listener, err := net.Listen("tcp", config.Port)
	if err != nil {
		return fmt.Errorf("error init Prometheus: %w", err)
	}

	server := &http.Server{Addr: listener.Addr().String(), Handler: mux}
	b.prometheusServer = server
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Errorf("Error serving Prometheus: %s", err.Error())
		}
	}()
	return nil
}

// build returns the assembled builder.
//
// The builder is returned as is instead of being copied: the event strategies
// hold a reference to it, so a copy would split the runtime state — the log
// file, the RabbitMQ channels and the syslog client would stay on one side
// while the running builder used the other, and the resources opened during
// the assembly would never be released.
func (b *Builder) build() *Builder {
	return b
}

func NewBuilder() *Builder {
	return &Builder{}
}
