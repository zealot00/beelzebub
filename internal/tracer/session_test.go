package tracer

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSourceKeyIsStableAndScoped(t *testing.T) {
	key := SourceKey("HTTP", ":8080", "10.0.0.5")

	assert.Equal(t, "HTTP|:8080|10.0.0.5", key)
	assert.Equal(t, key, SourceKey("HTTP", ":8080", "10.0.0.5"))
	assert.NotEqual(t, key, SourceKey("HTTP", ":8081", "10.0.0.5"))
	assert.NotEqual(t, key, SourceKey("HTTP", ":8080", "10.0.0.6"))
}

func TestSourceSessionIsStableForTheSameSource(t *testing.T) {
	ResetSourceSessions()
	defer ResetSourceSessions()

	first := SourceSession("HTTP", "10.0.0.5")
	second := SourceSession("HTTP", "10.0.0.5")

	assert.Equal(t, first, second)
	assert.NotEmpty(t, first)
}

func TestSourceSessionSeparatesProtocolsAndSources(t *testing.T) {
	ResetSourceSessions()
	defer ResetSourceSessions()

	http := SourceSession("HTTP", "10.0.0.5")
	mcp := SourceSession("MCP", "10.0.0.5")
	other := SourceSession("HTTP", "10.0.0.6")

	assert.NotEqual(t, http, mcp)
	assert.NotEqual(t, http, other)
}

func TestSourceSessionExpiresAfterTheInactivityWindow(t *testing.T) {
	ResetSourceSessions()
	defer ResetSourceSessions()

	original := SourceSessionTTL
	SourceSessionTTL = time.Millisecond
	defer func() { SourceSessionTTL = original }()

	first := SourceSession("HTTP", "10.0.0.5")
	time.Sleep(10 * time.Millisecond)
	second := SourceSession("HTTP", "10.0.0.5")

	assert.NotEqual(t, first, second, "an expired session must not be reused")
}

func TestPruneSourceSessionsDropsTheIdleOnes(t *testing.T) {
	ResetSourceSessions()
	defer ResetSourceSessions()

	original := SourceSessionTTL
	SourceSessionTTL = time.Millisecond
	defer func() { SourceSessionTTL = original }()

	SourceSession("HTTP", "10.0.0.5")
	time.Sleep(10 * time.Millisecond)
	PruneSourceSessions()

	sourceSessionMu.Lock()
	defer sourceSessionMu.Unlock()
	assert.Empty(t, sourceSessions)
}
