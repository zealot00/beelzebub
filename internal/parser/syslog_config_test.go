package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

func TestValidateCoreSyslog(t *testing.T) {
	tests := []struct {
		name      string
		conf      Syslog
		wantError bool
	}{
		{
			name: "disabled is always valid",
			conf: Syslog{Enabled: false, Address: "", Protocol: "sctp"},
		},
		{
			name:      "enabled without address",
			conf:      Syslog{Enabled: true},
			wantError: true,
		},
		{
			name:      "address without port",
			conf:      Syslog{Enabled: true, Address: "logs.internal"},
			wantError: true,
		},
		{
			name:      "unknown protocol",
			conf:      Syslog{Enabled: true, Address: "logs.internal:514", Protocol: "sctp"},
			wantError: true,
		},
		{
			name:      "unknown framing",
			conf:      Syslog{Enabled: true, Address: "logs.internal:514", Protocol: "tcp", Framing: "smoke"},
			wantError: true,
		},
		{
			name:      "unknown facility",
			conf:      Syslog{Enabled: true, Address: "logs.internal:514", Protocol: "tcp", Facility: "nowhere"},
			wantError: true,
		},
		{
			name:      "unknown severity",
			conf:      Syslog{Enabled: true, Address: "logs.internal:514", Protocol: "tcp", Severity: "loud"},
			wantError: true,
		},
		{
			name:      "tls over udp",
			conf:      Syslog{Enabled: true, Address: "logs.internal:514", Protocol: "udp", TLS: SyslogTLS{Enabled: true}},
			wantError: true,
		},
		{
			name:      "tls certificate without key",
			conf:      Syslog{Enabled: true, Address: "logs.internal:514", Protocol: "tcp", TLS: SyslogTLS{Enabled: true, CertFile: "cert.pem"}},
			wantError: true,
		},
		{
			name: "complete configuration",
			conf: Syslog{
				Enabled:  true,
				Address:  "logs.internal:514",
				Protocol: "tcp",
				Framing:  "octet-counted",
				Facility: "local3",
				Severity: "auto",
			},
		},
		{
			name: "tls over tcp",
			conf: Syslog{
				Enabled:  true,
				Address:  "logs.internal:6514",
				Protocol: "tcp",
				TLS:      SyslogTLS{Enabled: true, CAFile: "ca.pem"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := validateSyslog(tt.conf, "beelzebub.yaml")

			if tt.wantError {
				assert.NotEmpty(t, issues, "an error was expected")
				for _, issue := range issues {
					assert.Equal(t, LevelError, issue.Level)
				}
				return
			}

			assert.Empty(t, issues)
		})
	}
}

func TestSyslogIsParsedFromTheCoreConfiguration(t *testing.T) {
	config := &BeelzebubCoreConfigurations{}
	err := yaml.Unmarshal([]byte(`
core:
  tracings:
    syslog:
      enabled: true
      address: "logs.internal:6514"
      protocol: "tcp"
      framing: "non-transparent"
      facility: "local3"
      severity: "warning"
      app-name: "honeypot"
      timeout-seconds: 9
      tls:
        enabled: true
        ca-file: "/etc/ssl/ca.pem"
`), config)

	assert.NoError(t, err)
	syslog := config.Core.Tracings.Syslog
	assert.True(t, syslog.Enabled)
	assert.Equal(t, "logs.internal:6514", syslog.Address)
	assert.Equal(t, "tcp", syslog.Protocol)
	assert.Equal(t, "non-transparent", syslog.Framing)
	assert.Equal(t, "local3", syslog.Facility)
	assert.Equal(t, "warning", syslog.Severity)
	assert.Equal(t, "honeypot", syslog.AppName)
	assert.Equal(t, 9, syslog.TimeoutSeconds)
	assert.True(t, syslog.TLS.Enabled)
	assert.Equal(t, "/etc/ssl/ca.pem", syslog.TLS.CAFile)
}
