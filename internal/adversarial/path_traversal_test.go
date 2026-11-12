// Package adversarial holds the automated adversarial tests of the runtime.
//
// The tests are grouped by the attack they exercise: a path traversal, a
// container escape, and a prompt jailbreak. They assert the properties that
// must hold when the decoy is under attack, and they are meant to fail loudly
// when one of them regresses.
package adversarial

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/beelzebub-labs/beelzebub/v3/internal/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// traversalPaths are the request paths an attacker uses to reach a file that
// is outside of the decoy.
var traversalPaths = []string{
	"/../../../../etc/passwd",
	"/../../../../../../etc/shadow",
	"/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
	"/....//....//etc/passwd",
	"/static/../../../../../etc/hosts",
	"/a/b/c/../../../../../../root/.ssh/id_rsa",
	"/\\..\\..\\..\\etc\\passwd",
	"/%00/../../etc/passwd",
}

// TestTheDecoyNeverServesALocalFile is the path traversal suite.
//
// The decoy content is generated, never read from the disk: a request that
// tries to escape the decoy must be answered with synthetic content, and
// must never disclose a file of the host.
func TestTheDecoyNeverServesALocalFile(t *testing.T) {
	// The content of the file the attacker is after. The test asserts it
	// never appears in an answer.
	secrets, err := os.ReadFile("/etc/passwd")
	if err == nil {
		t.Logf("the host /etc/passwd is used as the reference secret")
	}

	for _, requestPath := range traversalPaths {
		t.Run(requestPath, func(t *testing.T) {
			maze := &plugins.MazeHoneypot{
				ServerVersion: "Apache/2.4.41 (Ubuntu)",
				ServerName:    "files.internal.company.com",
			}

			request := newRequest(requestPath)
			response := maze.HandleRequest(request)

			body := response.Body
			require.NotEmpty(t, body, "the decoy must always answer something")

			// The decoy normalises the path and answers with a synthetic
			// listing: the attacker sees a fake directory, never the file.
			// The check is therefore made against the real content of the
			// host file, line by line.
			if len(secrets) > 0 {
				for _, line := range strings.Split(string(secrets), "\n") {
					line = strings.TrimSpace(line)
					// The trivial lines of the file ("#", "##") would match
					// any generated content: only the meaningful ones are
					// a disclosure.
					if len(line) < 10 {
						continue
					}
					assert.NotContains(t, body, line,
						"the answer must not disclose a line of the host passwd file")
				}
			}

			assert.NotContains(t, body, "BEGIN OPENSSH PRIVATE KEY", "the answer must not disclose a private key")
			assert.NotContains(t, body, "root:x:0:0", "the answer must not disclose the host passwd file")

			// The answer is the generated one: a listing for a directory, a
			// synthetic file for a file.
			assert.True(t,
				strings.Contains(body, "Index of") || strings.Contains(body, "# Auto-generated file"),
				"the answer must be the generated content")
		})
	}
}

// TestTheSampleStoreStaysInsideItsRoot is the path traversal suite applied to
// the evidence store.
//
// The attacker controls the request URI, and the name it suggests. The store
// must never write outside of its root, whatever the name is.
func TestTheSampleStoreStaysInsideItsRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "samples")
	require.NoError(t, os.MkdirAll(root, 0o700))

	canary := filepath.Join(filepath.Dir(root), "canary.txt")
	require.NoError(t, os.WriteFile(canary, []byte("intact"), 0o600))

	store := newEvidenceStore(t, root)

	names := []string{
		"../../../../etc/passwd",
		"..%2f..%2fetc%2fpasswd",
		"....//....//etc/passwd",
		"/etc/passwd",
		"a/../../../b",
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			store.Handle(newHTTPEvent(strings.Repeat("A", 256), "/uploads/"+name))

			// The canary is untouched.
			content, err := os.ReadFile(canary)
			require.NoError(t, err)
			assert.Equal(t, "intact", string(content))

			// Every stored file is under the root.
			for _, path := range walkFiles(t, root) {
				relative, err := filepath.Rel(root, path)
				require.NoError(t, err)
				assert.False(t, strings.HasPrefix(relative, ".."),
					"the file %q escaped the root of the store", path)
			}
		})
	}
}

// walkFiles lists every file under a directory.
func walkFiles(t *testing.T, root string) []string {
	t.Helper()

	var files []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	require.NoError(t, err)

	return files
}
