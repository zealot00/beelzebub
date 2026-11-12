package builder

import (
	"context"
	"encoding/json"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/internal/plugins"
	"github.com/beelzebub-labs/beelzebub/v3/internal/tracer"

	amqp "github.com/rabbitmq/amqp091-go"
	log "github.com/sirupsen/logrus"
)

type Director struct {
	builder *Builder
}

func NewDirector(builder *Builder) *Director {
	return &Director{
		builder: builder,
	}
}

// BuildBeelzebub assembles the runtime.
//
// The event sinks are composed into a fan-out: the local log is always
// present and every additional output (RabbitMQ, syslog, Beelzebub Cloud)
// receives the same events. Sinks no longer replace each other.
func (d *Director) BuildBeelzebub(beelzebubCoreConfigurations *parser.BeelzebubCoreConfigurations, beelzebubServicesConfiguration []parser.BeelzebubServiceConfiguration) (*Builder, error) {
	d.builder.beelzebubServicesConfiguration = beelzebubServicesConfiguration
	d.builder.beelzebubCoreConfigurations = beelzebubCoreConfigurations
	if err := d.builder.buildLogger(beelzebubCoreConfigurations.Core.Logging); err != nil {
		return nil, err
	}

	d.builder.setTraceStrategies([]tracer.Strategy{d.standardOutStrategy})

	if beelzebubCoreConfigurations.Core.Tracings.RabbitMQ.Enabled {
		d.builder.addTraceStrategy(d.rabbitMQTraceStrategy)
		err := d.builder.buildRabbitMQ(beelzebubCoreConfigurations.Core.Tracings.RabbitMQ.URI)
		if err != nil {
			return nil, err
		}
	}

	if beelzebubCoreConfigurations.Core.Tracings.Syslog.Enabled {
		d.builder.addTraceStrategy(d.syslogTraceStrategy)
		if err := d.builder.buildSyslog(beelzebubCoreConfigurations.Core.Tracings.Syslog); err != nil {
			return nil, err
		}
	}

	if beelzebubCoreConfigurations.Core.BeelzebubCloud.Enabled {
		d.builder.addTraceStrategy(d.beelzebubCloudStrategy)
	}

	return d.builder.build(), nil
}

// standardOutStrategy writes the event to the local log.
//
// It is the base sink: it is always installed, and the other sinks add their
// own delivery on top of it.
func (d *Director) standardOutStrategy(event tracer.Event) {
	log.WithFields(log.Fields{
		"status": event.Status,
		"event":  event,
	}).Info("New Event")
}

// beelzebubCloudStrategy publishes the event to the Beelzebub Cloud.
func (d *Director) beelzebubCloudStrategy(event tracer.Event) {
	conf := d.builder.beelzebubCoreConfigurations.Core.BeelzebubCloud

	beelzebubCloud := plugins.InitBeelzebubCloud(conf.URI, conf.AuthToken, false)

	result, err := beelzebubCloud.SendEvent(event)
	if err != nil {
		log.Error(err.Error())
	} else {
		log.WithFields(log.Fields{
			"status": result,
			"event":  event,
		}).Debug("Event published on beelzebub cloud")
	}
}

// rabbitMQTraceStrategy publishes the event on the RabbitMQ queue.
func (d *Director) rabbitMQTraceStrategy(event tracer.Event) {
	eventJSON, err := json.Marshal(event)
	if err != nil {
		log.Error(err.Error())
		return
	}

	publishing := amqp.Publishing{ContentType: "application/json", Body: eventJSON}

	if err = d.builder.rabbitMQChannel.PublishWithContext(context.TODO(), "", RabbitmqQueueName, false, false, publishing); err != nil {
		log.Error(err.Error())
	} else {
		log.WithFields(log.Fields{
			"status": event.Status,
			"event":  event,
		}).Debug("Event published")
	}
}

// syslogTraceStrategy ships the event to the configured syslog server.
//
// Failures are logged but never interrupt the honeypot: a log server outage
// must not stop the capture.
func (d *Director) syslogTraceStrategy(event tracer.Event) {
	if d.builder.syslogClient == nil {
		return
	}

	if err := d.builder.syslogClient.Send(event); err != nil {
		log.WithField("error", err.Error()).Warn("Unable to deliver the event to the syslog server")
	}
}
