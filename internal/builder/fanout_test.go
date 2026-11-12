package builder

import (
	"testing"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/internal/tracer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBuildBeelzebub_ComposesEveryOutput is the regression test for the
// fan-out: enabling an additional output must add a sink instead of
// replacing the previously configured ones.
func TestBuildBeelzebub_ComposesEveryOutput(t *testing.T) {
	b := NewBuilder()
	d := NewDirector(b)

	coreConfig := &parser.BeelzebubCoreConfigurations{}
	coreConfig.Core.Tracings.Syslog.Enabled = true
	coreConfig.Core.Tracings.Syslog.Address = "127.0.0.1:5514"
	coreConfig.Core.BeelzebubCloud.Enabled = true
	coreConfig.Core.BeelzebubCloud.URI = "http://127.0.0.1:1"
	coreConfig.Core.BeelzebubCloud.AuthToken = "token"

	result, err := d.BuildBeelzebub(coreConfig, nil)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, result.Close()) })

	// The local log, the syslog pipeline and the cloud reporting are all
	// installed: three independent sinks.
	assert.Len(t, result.traceStrategies, 3)
	assert.NotNil(t, result.syslogClient)
}

func TestBuildBeelzebub_AlwaysKeepsTheLocalLog(t *testing.T) {
	b := NewBuilder()
	d := NewDirector(b)

	result, err := d.BuildBeelzebub(&parser.BeelzebubCoreConfigurations{}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, result.Close()) })

	assert.Len(t, result.traceStrategies, 1)
}

func TestBuildBeelzebub_RejectsAnInvalidSyslogConfiguration(t *testing.T) {
	b := NewBuilder()
	d := NewDirector(b)

	coreConfig := &parser.BeelzebubCoreConfigurations{}
	coreConfig.Core.Tracings.Syslog.Enabled = true
	coreConfig.Core.Tracings.Syslog.Address = "127.0.0.1:514"
	coreConfig.Core.Tracings.Syslog.Protocol = "sctp"

	_, err := d.BuildBeelzebub(coreConfig, nil)
	assert.Error(t, err)
}

func TestSyslogTraceStrategyNeverPanicsWithoutAClient(t *testing.T) {
	b := NewBuilder()
	d := NewDirector(b)

	// The strategy must stay silent when the syslog pipeline is disabled.
	assert.NotPanics(t, func() {
		d.syslogTraceStrategy(tracer.Event{Protocol: "HTTP"})
	})
}
