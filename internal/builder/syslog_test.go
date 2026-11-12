package builder

import (
	"bufio"
	"encoding/json"
	"net"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/internal/tracer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// octetCountedPattern matches the RFC 6587 octet counted framing.
var octetCountedPattern = regexp.MustCompile(`^\d+ `)

func testSyslogConfig() parser.Syslog {
	return parser.Syslog{
		Enabled:        true,
		Address:        "127.0.0.1:514",
		Protocol:       "tcp",
		Framing:        "octet-counted",
		Facility:       "local0",
		Severity:       "auto",
		AppName:        "beelzebub",
		TimeoutSeconds: 2,
	}
}

func TestNewSyslogClientRejectsUnknownValues(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(conf *parser.Syslog)
	}{
		{"unknown facility", func(conf *parser.Syslog) { conf.Facility = "not-a-facility" }},
		{"unknown severity", func(conf *parser.Syslog) { conf.Severity = "not-a-severity" }},
		{"unknown protocol", func(conf *parser.Syslog) { conf.Protocol = "sctp" }},
		{"unknown framing", func(conf *parser.Syslog) { conf.Framing = "smoke-signals" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf := testSyslogConfig()
			tt.mutate(&conf)

			_, err := newSyslogClient(conf)
			assert.Error(t, err)
		})
	}
}

func TestNewSyslogClientAppliesTheDefaults(t *testing.T) {
	client, err := newSyslogClient(parser.Syslog{Enabled: true, Address: "127.0.0.1:514"})
	require.NoError(t, err)

	assert.Equal(t, syslogProtocolTCP, client.protocol)
	assert.Equal(t, syslogFramingOctetCounted, client.framing)
	assert.Equal(t, syslogFacilities["local0"], client.facility)
	assert.True(t, client.severityAuto)
	assert.Equal(t, syslogDefaultAppName, client.appName)
	assert.Equal(t, 5*time.Second, client.timeout)
}

func TestSyslogMessageFollowsRFC5424(t *testing.T) {
	client, err := newSyslogClient(testSyslogConfig())
	require.NoError(t, err)

	event := tracer.Event{
		DateTime:       "2026-11-12T10:00:00Z",
		Protocol:       "HTTP",
		Status:         tracer.Interaction.String(),
		SourceIp:       "10.0.0.5",
		SessionID:      "session-1",
		CorrelationKey: "HTTP|:8080|10.0.0.5",
		EventID:        "event-1",
		Command:        "GET /admin",
	}

	raw := string(client.format(event))

	// Octet counted framing: "<length> <message>".
	space := strings.Index(raw, " ")
	require.Greater(t, space, 0)
	length, err := strconv.Atoi(raw[:space])
	require.NoError(t, err)
	message := raw[space+1:]
	assert.Equal(t, len(message), length, "the octet count must match the payload length")

	assert.True(t, strings.HasPrefix(message, "<132>1 "), "facility local0 and severity warning give priority 132")
	assert.Contains(t, message, " beelzebub ")
	assert.Contains(t, message, " http ")
	assert.Contains(t, message, "[beelzebub@32473 ")
	assert.Contains(t, message, `src="10.0.0.5"`)
	assert.Contains(t, message, `session="session-1"`)
	assert.Contains(t, message, `eventid="event-1"`)

	// The message part is the JSON encoded event: it starts after the
	// structured data element.
	sdStart := strings.Index(message, "["+syslogSDID+"@")
	require.Greater(t, sdStart, 0)
	sdEnd := strings.Index(message[sdStart:], "]")
	require.Greater(t, sdEnd, 0)
	payload := strings.TrimSpace(message[sdStart+sdEnd+1:])
	var decoded tracer.Event
	require.NoError(t, json.Unmarshal([]byte(payload), &decoded))
	assert.Equal(t, "GET /admin", decoded.Command)
	assert.Equal(t, "session-1", decoded.SessionID)
}

func TestSyslogFramingNonTransparent(t *testing.T) {
	conf := testSyslogConfig()
	conf.Framing = "non-transparent"

	client, err := newSyslogClient(conf)
	require.NoError(t, err)

	raw := string(client.format(tracer.Event{Protocol: "TCP"}))
	assert.True(t, strings.HasSuffix(raw, "\n"))
	assert.False(t, octetCountedPattern.MatchString(raw), "the payload must not be length prefixed")
	assert.True(t, strings.HasPrefix(raw, "<134>1 "))
}

func TestSyslogSeverityFollowsTheEventStatus(t *testing.T) {
	client, err := newSyslogClient(testSyslogConfig())
	require.NoError(t, err)

	stateless := string(client.format(tracer.Event{Status: tracer.Stateless.String()}))
	interaction := string(client.format(tracer.Event{Status: tracer.Interaction.String()}))
	start := string(client.format(tracer.Event{Status: tracer.Start.String()}))

	assert.Contains(t, stateless, "<133>1 ", "a probe maps to notice")
	assert.Contains(t, interaction, "<132>1 ", "an interaction maps to warning")
	assert.Contains(t, start, "<134>1 ", "a session start maps to informational")
}

func TestSyslogSeverityCanBePinned(t *testing.T) {
	conf := testSyslogConfig()
	conf.Severity = "error"

	client, err := newSyslogClient(conf)
	require.NoError(t, err)

	raw := string(client.format(tracer.Event{Status: tracer.Interaction.String()}))
	assert.Contains(t, raw, "<131>1 ", "facility local0 and severity error give priority 131")
}

func TestEscapeSyslogParam(t *testing.T) {
	assert.Equal(t, `a\\b`, escapeSyslogParam(`a\b`))
	assert.Equal(t, `a\"b`, escapeSyslogParam(`a"b`))
	assert.Equal(t, `a\]b`, escapeSyslogParam(`a]b`))
}

func TestSyslogClientSendsOverTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	received := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		// Read the octet counted frame.
		lengthText, err := reader.ReadString(' ')
		if err != nil {
			return
		}
		length, err := strconv.Atoi(strings.TrimSpace(lengthText))
		if err != nil {
			return
		}
		payload := make([]byte, length)
		if _, err := reader.Read(payload); err != nil {
			return
		}
		received <- string(payload)
	}()

	conf := testSyslogConfig()
	conf.Address = listener.Addr().String()

	client, err := newSyslogClient(conf)
	require.NoError(t, err)
	defer client.Close()

	event := tracer.Event{
		DateTime: "2026-11-12T10:00:00Z",
		Protocol: "SSH",
		Status:   tracer.Stateless.String(),
		SourceIp: "10.1.2.3",
		Command:  "root",
	}
	require.NoError(t, client.Send(event))

	select {
	case message := <-received:
		assert.Contains(t, message, "<133>1 ")
		assert.Contains(t, message, `src="10.1.2.3"`)
		assert.Contains(t, message, `"Command":"root"`)
	case <-time.After(3 * time.Second):
		t.Fatal("the syslog server did not receive the event")
	}
}

func TestSyslogClientSendsOverUDP(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn.Close()

	received := make(chan string, 1)
	go func() {
		buffer := make([]byte, 65535)
		n, _, err := conn.ReadFrom(buffer)
		if err != nil {
			return
		}
		received <- string(buffer[:n])
	}()

	conf := testSyslogConfig()
	conf.Protocol = "udp"
	conf.Address = conn.LocalAddr().String()

	client, err := newSyslogClient(conf)
	require.NoError(t, err)
	defer client.Close()

	require.NoError(t, client.Send(tracer.Event{Protocol: "TCP", SourceIp: "10.9.9.9"}))

	select {
	case message := <-received:
		assert.True(t, strings.HasSuffix(message, "\n"))
		assert.Contains(t, message, `"SourceIp":"10.9.9.9"`)
	case <-time.After(3 * time.Second):
		t.Fatal("the syslog server did not receive the event")
	}
}

func TestSyslogClientReportsAnUnreachableServer(t *testing.T) {
	conf := testSyslogConfig()
	conf.Address = "127.0.0.1:1"
	conf.TimeoutSeconds = 1

	client, err := newSyslogClient(conf)
	require.NoError(t, err)
	defer client.Close()

	assert.Error(t, client.Send(tracer.Event{Protocol: "HTTP"}))
}
