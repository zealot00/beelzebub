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

			// The answer must be one of the answers of the decoy itself:
			// the generated file, the generated system file or the
			// generated listing. It can never be a file of the host.
			assert.True(t, isGeneratedAnswer(body),
				"the answer must be one of the generated answers of the decoy")

			// And it must never be the file of the host the attacker aimed
			// at, byte for byte.
			for hostPath, hostContent := range hostFileContents(t) {
				assert.NotEqual(t, hostContent, body,
					"the answer must not be the file %s of the host", hostPath)
			}
		})
	}
}

// isGeneratedAnswer reports whether the body is one of the generated answers.
func isGeneratedAnswer(body string) bool {
	return strings.Contains(body, "# Auto-generated file") ||
		strings.Contains(body, "Index of") ||
		strings.Contains(body, "root:x:0:0:root:/root:/bin/bash") ||
		strings.Contains(body, "root:*:19000:0:99999:7:::") ||
		strings.Contains(body, "BEGIN OPENSSH PRIVATE KEY") ||
		strings.Contains(body, "PRETTY_NAME=") ||
		strings.Contains(body, "127.0.0.1\tlocalhost") ||
		strings.Contains(body, "Linux version ") ||
		strings.Contains(body, "SHELL=/bin/sh") ||
		strings.Contains(body, "export PATH=") ||
		strings.Contains(body, "Accepted password for") ||
		strings.Contains(body, "Ubuntu 22.04.3 LTS")
}

// hostFileContents reads the files of the host the attacker aims at.
func hostFileContents(t *testing.T) map[string]string {
	t.Helper()

	paths := []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/hosts",
		"/etc/hostname",
		"/etc/os-release",
		"/etc/group",
		"/etc/issue",
		"/etc/resolv.conf",
		"/etc/crontab",
	}

	contents := map[string]string{}
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		contents[path] = string(content)
	}

	return contents
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
