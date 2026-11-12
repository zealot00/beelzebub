package tracer

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// SourceSessionTTL is the inactivity window after which a source session is
// considered closed and a new one is started.
var SourceSessionTTL = 30 * time.Minute

type sourceSession struct {
	id       string
	lastSeen time.Time
}

var (
	sourceSessionMu sync.Mutex
	sourceSessions  = make(map[string]*sourceSession)
)

// SourceKey builds the correlation key that groups every event observed from
// the same source on the same service.
//
// The key is stable across connections and sessions: it is the join key used
// to rebuild an attack chain that spans several connections, which is the
// normal case for HTTP scanners and MCP agents.
func SourceKey(protocol, service, sourceIP string) string {
	return protocol + "|" + service + "|" + sourceIP
}

// SourceSession returns a stable session identifier for a source address.
//
// Connectionless protocols (HTTP, MCP) have no transport session to hang an
// identifier on, so a rolling session per source is used instead: every event
// from the same source shares the identifier until the source has been idle
// for SourceSessionTTL, at which point a new session starts.
//
// The returned identifier is never empty.
func SourceSession(protocol, sourceIP string) string {
	key := protocol + "|" + sourceIP

	sourceSessionMu.Lock()
	defer sourceSessionMu.Unlock()

	now := time.Now()
	if session, ok := sourceSessions[key]; ok {
		if now.Sub(session.lastSeen) <= SourceSessionTTL {
			session.lastSeen = now
			return session.id
		}
	}

	session := &sourceSession{id: uuid.New().String(), lastSeen: now}
	sourceSessions[key] = session
	return session.id
}

// ResetSourceSessions clears the rolling source sessions. It exists for tests
// and for the runtime shutdown path.
func ResetSourceSessions() {
	sourceSessionMu.Lock()
	defer sourceSessionMu.Unlock()
	sourceSessions = make(map[string]*sourceSession)
}

// PruneSourceSessions drops the source sessions that have been idle for longer
// than SourceSessionTTL. It keeps the rolling session table bounded.
func PruneSourceSessions() {
	sourceSessionMu.Lock()
	defer sourceSessionMu.Unlock()

	now := time.Now()
	for key, session := range sourceSessions {
		if now.Sub(session.lastSeen) > SourceSessionTTL {
			delete(sourceSessions, key)
		}
	}
}
