package adversarial

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/beelzebub-labs/beelzebub/v3/internal/evidence"
	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/pkg/plugin"
	"github.com/stretchr/testify/require"
)

// newRequest builds a GET request for the given path.
func newRequest(path string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "http://decoy.internal"+path, nil)
	request.RemoteAddr = "10.0.0.5:51234"
	return request
}

// newEvidenceStore builds a sample store rooted at the given directory.
func newEvidenceStore(t *testing.T, root string) *evidence.Store {
	t.Helper()

	store, err := evidence.NewStore(parser.Evidence{
		Enabled:      true,
		Path:         root,
		MinSizeBytes: 16,
		MaxSizeBytes: 1 << 20,
	})
	require.NoError(t, err)

	return store
}

// newHTTPEvent builds the event of an HTTP request carrying a body.
func newHTTPEvent(body, requestURI string) plugin.Event {
	return plugin.Event{
		Protocol:   "HTTP",
		Body:       body,
		RequestURI: requestURI,
		SourceIp:   "10.0.0.5",
		EventID:    "adversarial-event",
		DateTime:   "2026-11-12T10:00:00Z",
	}
}
