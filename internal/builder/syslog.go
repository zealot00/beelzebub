package builder

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/internal/tracer"
)

const (
	// syslogEnterpriseID is the private enterprise number used for the
	// structured data element of the RFC 5424 payload.
	syslogEnterpriseID = 32473
	// syslogSDID is the structured data identifier of the Beelzebub element.
	syslogSDID = "beelzebub"

	syslogDefaultFacility = "local0"
	syslogDefaultSeverity = "auto"
	syslogDefaultAppName  = "beelzebub"
	syslogDefaultProtocol = "tcp"
	syslogDefaultFraming  = "octet-counted"
	syslogDefaultTimeout  = 5
)

// Syslog transports.
const (
	syslogProtocolTCP = "tcp"
	syslogProtocolUDP = "udp"
)

// Syslog TCP framings (RFC 6587).
const (
	syslogFramingOctetCounted   = "octet-counted"
	syslogFramingNonTransparent = "non-transparent"
)

// syslogFacilities maps the RFC 5424 facility names to their numeric value.
var syslogFacilities = map[string]int{
	"kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5,
	"lpr": 6, "news": 7, "uucp": 8, "cron": 9, "authpriv": 10, "ftp": 11,
	"local0": 16, "local1": 17, "local2": 18, "local3": 19,
	"local4": 20, "local5": 21, "local6": 22, "local7": 23,
}

// syslogSeverities maps the RFC 5424 severity names to their numeric value.
var syslogSeverities = map[string]int{
	"emergency": 0, "alert": 1, "critical": 2, "error": 3,
	"warning": 4, "notice": 5, "informational": 6, "debug": 7,
}

// syslogAliases accepts the common short names of the severities.
var syslogAliases = map[string]int{
	"panic": 0, "crit": 2, "err": 3, "warn": 4, "info": 6,
}

// syslogClient ships runtime events to a syslog server.
//
// The connection is established lazily and re-established after a failure, so
// a log server that is down never prevents the honeypot from running.
type syslogClient struct {
	address  string
	protocol string
	framing  string

	facility     int
	severity     int
	severityAuto bool
	appName      string
	hostname     string
	pid          string
	timeout      time.Duration

	tlsConfig *tls.Config

	mu     sync.Mutex
	conn   net.Conn
	closed bool
}

// newSyslogClient builds a syslog sink from the core configuration.
func newSyslogClient(conf parser.Syslog) (*syslogClient, error) {
	facilityName := strings.ToLower(strings.TrimSpace(conf.Facility))
	if facilityName == "" {
		facilityName = syslogDefaultFacility
	}
	facility, ok := syslogFacilities[facilityName]
	if !ok {
		return nil, fmt.Errorf("unknown syslog facility %q", conf.Facility)
	}

	severityName := strings.ToLower(strings.TrimSpace(conf.Severity))
	if severityName == "" {
		severityName = syslogDefaultSeverity
	}
	severity, severityAuto := 0, false
	if severityName == "auto" {
		severityAuto = true
		severity = syslogSeverities["informational"]
	} else if value, found := syslogSeverities[severityName]; found {
		severity = value
	} else if value, found := syslogAliases[severityName]; found {
		severity = value
	} else {
		return nil, fmt.Errorf("unknown syslog severity %q", conf.Severity)
	}

	protocol := strings.ToLower(strings.TrimSpace(conf.Protocol))
	if protocol == "" {
		protocol = syslogDefaultProtocol
	}
	if protocol != syslogProtocolTCP && protocol != syslogProtocolUDP {
		return nil, fmt.Errorf("unknown syslog protocol %q", conf.Protocol)
	}

	framing := strings.ToLower(strings.TrimSpace(conf.Framing))
	if framing == "" {
		framing = syslogDefaultFraming
	}
	if framing != syslogFramingOctetCounted && framing != syslogFramingNonTransparent {
		return nil, fmt.Errorf("unknown syslog framing %q", conf.Framing)
	}

	appName := strings.TrimSpace(conf.AppName)
	if appName == "" {
		appName = syslogDefaultAppName
	}

	timeout := time.Duration(conf.TimeoutSeconds) * time.Second
	if conf.TimeoutSeconds <= 0 {
		timeout = syslogDefaultTimeout * time.Second
	}

	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "localhost"
	}

	client := &syslogClient{
		address:      conf.Address,
		protocol:     protocol,
		framing:      framing,
		facility:     facility,
		severity:     severity,
		severityAuto: severityAuto,
		appName:      appName,
		hostname:     hostname,
		pid:          strconv.Itoa(os.Getpid()),
		timeout:      timeout,
	}

	if conf.TLS.Enabled {
		if protocol != syslogProtocolTCP {
			return nil, fmt.Errorf("syslog TLS requires the tcp protocol")
		}
		tlsConfig, err := buildSyslogTLSConfig(conf.TLS)
		if err != nil {
			return nil, err
		}
		client.tlsConfig = tlsConfig
	}

	return client, nil
}

// buildSyslogTLSConfig assembles the TLS configuration of the syslog sink.
func buildSyslogTLSConfig(conf parser.SyslogTLS) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: conf.InsecureSkipVerify, //nolint:gosec // opt-in, documented in the configuration
		MinVersion:         tls.VersionTLS12,
	}

	if conf.CertFile != "" || conf.KeyFile != "" {
		certificate, err := tls.LoadX509KeyPair(conf.CertFile, conf.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("syslog TLS key pair: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}

	if conf.CAFile != "" {
		pem, err := os.ReadFile(conf.CAFile)
		if err != nil {
			return nil, fmt.Errorf("syslog TLS CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("syslog TLS CA file %q contains no usable certificate", conf.CAFile)
		}
		tlsConfig.RootCAs = pool
	}

	return tlsConfig, nil
}

// Send delivers one event to the syslog server.
func (c *syslogClient) Send(event tracer.Event) error {
	if c == nil {
		return nil
	}

	message := c.format(event)

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return fmt.Errorf("syslog client is closed")
	}

	if err := c.ensureConn(); err != nil {
		return err
	}

	if err := c.conn.SetWriteDeadline(time.Now().Add(c.timeout)); err != nil {
		return err
	}

	if _, err := c.conn.Write(message); err != nil {
		// Drop the broken connection: the next event re-establishes it.
		c.closeConn()
		return fmt.Errorf("syslog write: %w", err)
	}

	return nil
}

// format renders the event as a RFC 5424 message, including the transport
// framing.
func (c *syslogClient) format(event tracer.Event) []byte {
	severity := c.severity
	if c.severityAuto {
		severity = severityForStatus(event.Status, severity)
	}

	pri := c.facility*8 + severity

	timestamp := event.DateTime
	if timestamp == "" {
		timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	msgID := strings.ToLower(event.Protocol)
	if msgID == "" {
		msgID = "event"
	}

	payload, err := json.Marshal(event)
	if err != nil {
		payload = []byte("{}")
	}

	header := fmt.Sprintf("<%d>1 %s %s %s %s %s %s ", pri, timestamp, c.hostname, c.appName, c.pid, msgID, c.structuredData(event))
	message := header + string(payload)

	if c.protocol == syslogProtocolTCP && c.framing == syslogFramingOctetCounted {
		return []byte(strconv.Itoa(len(message)) + " " + message)
	}
	return []byte(message + "\n")
}

// structuredData renders the Beelzebub structured data element.
func (c *syslogClient) structuredData(event tracer.Event) string {
	params := []string{
		fmt.Sprintf("src=%q", escapeSyslogParam(event.SourceIp)),
		fmt.Sprintf("proto=%q", escapeSyslogParam(event.Protocol)),
	}
	if event.SessionID != "" {
		params = append(params, fmt.Sprintf("session=%q", escapeSyslogParam(event.SessionID)))
	}
	if event.CorrelationKey != "" {
		params = append(params, fmt.Sprintf("correlation=%q", escapeSyslogParam(event.CorrelationKey)))
	}
	if event.EventID != "" {
		params = append(params, fmt.Sprintf("eventid=%q", escapeSyslogParam(event.EventID)))
	}

	return fmt.Sprintf("[%s@%d %s]", syslogSDID, syslogEnterpriseID, strings.Join(params, " "))
}

// severityForStatus derives the syslog severity from the event status when
// the configuration asks for the automatic mapping.
func severityForStatus(status string, fallback int) int {
	switch status {
	case tracer.Stateless.String():
		// A probe that never reached a real interaction.
		return syslogSeverities["notice"]
	case tracer.Interaction.String():
		// The attacker interacted with the decoy.
		return syslogSeverities["warning"]
	case tracer.Start.String(), tracer.End.String():
		return syslogSeverities["informational"]
	default:
		return fallback
	}
}

// escapeSyslogParam escapes a structured data parameter value as required by
// RFC 5424 section 6.3.3.
func escapeSyslogParam(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `]`, `\]`)
	return replacer.Replace(value)
}

// ensureConn returns a usable connection, dialling when needed.
func (c *syslogClient) ensureConn() error {
	if c.conn != nil {
		return nil
	}

	var conn net.Conn
	var err error

	dialer := &net.Dialer{Timeout: c.timeout}
	if c.protocol == syslogProtocolUDP {
		conn, err = dialer.Dial("udp", c.address)
	} else {
		conn, err = dialer.Dial("tcp", c.address)
		if err == nil && c.tlsConfig != nil {
			tlsConn := tls.Client(conn, c.tlsConfig)
			if err = tlsConn.Handshake(); err != nil {
				_ = conn.Close()
				return fmt.Errorf("syslog TLS handshake: %w", err)
			}
			conn = tlsConn
		}
	}
	if err != nil {
		return fmt.Errorf("syslog dial %s: %w", c.address, err)
	}

	c.conn = conn
	return nil
}

// closeConn drops the current connection, if any.
func (c *syslogClient) closeConn() {
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
}

// Close releases the syslog connection.
func (c *syslogClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.closed = true
	c.closeConn()
	return nil
}
