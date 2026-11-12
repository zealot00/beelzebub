package adversarial

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/beelzebub-labs/beelzebub/v3/internal/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// systemFileRequests are the paths an attacker reads first on a Linux host.
var systemFileRequests = []string{
	"/etc/passwd",
	"/etc/shadow",
	"/etc/hosts",
	"/etc/os-release",
	"/etc/issue",
	"/etc/hostname",
	"/etc/resolv.conf",
	"/etc/crontab",
	"/proc/version",
	"/root/.bash_history",
	"/root/.bashrc",
	"/root/.ssh/id_rsa",
	"/var/log/auth.log",
}

// TestTheWellKnownSystemFilesAreFiles asserts that the paths that are files
// on a real system are answered with a file.
//
// The name of those paths carries no extension: without the system file
// table, a request for /etc/passwd would be answered with a directory
// listing, and the attacker would know the host is a decoy before reading a
// single line.
func TestTheWellKnownSystemFilesAreFiles(t *testing.T) {
	maze := &plugins.MazeHoneypot{
		ServerVersion: "Apache/2.4.41 (Ubuntu)",
		ServerName:    "files.internal.company.com",
	}

	for _, requestPath := range systemFileRequests {
		t.Run(requestPath, func(t *testing.T) {
			response := maze.HandleRequest(newRequest(requestPath))

			assert.Equal(t, 200, response.StatusCode)
			assert.NotContains(t, response.Body, "Index of",
				"the answer must not be a directory listing")
			assert.NotContains(t, response.Body, "<!DOCTYPE HTML",
				"the answer must not be a directory listing")
			assert.NotEmpty(t, response.Body)
		})
	}
}

// TestTheGeneratedPasswdIsPlausibleAndInert asserts the shape of the
// generated passwd file, and that it holds nothing usable.
func TestTheGeneratedPasswdIsPlausibleAndInert(t *testing.T) {
	maze := &plugins.MazeHoneypot{}
	response := maze.HandleRequest(newRequest("/etc/passwd"))

	lines := strings.Split(strings.TrimSpace(response.Body), "\n")
	require.GreaterOrEqual(t, len(lines), 20, "a passwd file holds the system accounts")

	for _, line := range lines {
		fields := strings.Split(line, ":")
		require.Len(t, fields, 7, "the line %q must have the seven fields of a passwd entry", line)
		assert.Equal(t, "x", fields[1], "the password is never in the passwd file")
		assert.NotEmpty(t, fields[0])
		assert.NotEmpty(t, fields[6], "the shell must be set")
	}

	assert.Contains(t, response.Body, "root:x:0:0:root:/root:/bin/bash")
	assert.Contains(t, response.Body, "www-data:x:33:33")
}

// TestTheGeneratedShadowHoldsNoUsablePassword asserts that every password of
// the generated shadow file is locked, except the bait.
//
// A decoy that offers a crackable hash hands the attacker a real credential
// of a real system: the shadow file of the decoy must be inert. The single
// exception is the bait, whose password is documented and whose hash is
// salted: it is the marker the defender looks for.
func TestTheGeneratedShadowHoldsNoUsablePassword(t *testing.T) {
	maze := &plugins.MazeHoneypot{}
	response := maze.HandleRequest(newRequest("/etc/shadow"))

	lines := strings.Split(strings.TrimSpace(response.Body), "\n")
	require.GreaterOrEqual(t, len(lines), 20)

	usable := 0
	for _, line := range lines {
		fields := strings.Split(line, ":")
		require.Len(t, fields, 9, "the line %q must have the nine fields of a shadow entry", line)

		password := fields[1]
		if password == "*" || password == "!" || password == "!!" {
			continue
		}

		usable++
		// The bcrypt format carries its own salt: the prefix, the cost, the
		// twenty two characters of the salt and the thirty one of the hash.
		assert.Regexp(t, `^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$`, password,
			"the only usable password must be a salted bcrypt hash")
	}

	assert.Equal(t, 1, usable, "only the bait may hold a usable password")
}

// TestTheBaitIsRecognisable asserts that the bait of the decoy can be
// recognised by the defender.
//
// The account name is an ordinary service account — a decoy that names its
// bait tells the attacker what it is. What makes it recognisable is the
// password, which is documented.
func TestTheBaitIsRecognisable(t *testing.T) {
	maze := &plugins.MazeHoneypot{}
	passwd := maze.HandleRequest(newRequest("/etc/passwd")).Body

	var bait string
	for _, line := range strings.Split(strings.TrimSpace(passwd), "\n") {
		fields := strings.Split(line, ":")
		require.Len(t, fields, 7)
		if fields[1] != "x" {
			continue
		}
		if fields[0] == "root" || fields[0] == "deploy" {
			continue
		}
		if strings.Contains(fields[0], "backup") {
			bait = fields[0]
		}
	}

	require.NotEmpty(t, bait, "the decoy must offer a service account to the attacker")

	lowered := strings.ToLower(bait)
	for _, forbidden := range []string{"honey", "honeypot", "decoy", "trap", "bait", "canary"} {
		assert.NotContains(t, lowered, forbidden,
			"the name of the bait must not announce that the host is a decoy")
	}
}

// TestTheGeneratedFilesAreNotTheFilesOfTheHost asserts that the decoy never
// discloses a file of the machine it runs on.
func TestTheGeneratedFilesAreNotTheFilesOfTheHost(t *testing.T) {
	maze := &plugins.MazeHoneypot{}

	hostFiles := map[string]string{
		"/etc/passwd":     "/etc/passwd",
		"/etc/shadow":     "/etc/shadow",
		"/etc/hosts":      "/etc/hosts",
		"/etc/hostname":   "/etc/hostname",
		"/etc/os-release": "/etc/os-release",
	}

	for requestPath, hostPath := range hostFiles {
		t.Run(requestPath, func(t *testing.T) {
			host, err := os.ReadFile(hostPath)
			if err != nil {
				t.Skipf("the host file %s is not readable", hostPath)
			}

			response := maze.HandleRequest(newRequest(requestPath))

			assert.NotEqual(t, string(host), response.Body,
				"the answer must not be the file of the host")
		})
	}
}

// TestTheGeneratedFilesAreStable asserts that the same path always answers
// the same content.
//
// An attacker who reads /etc/passwd twice and gets two different accounts
// knows he is talking to a decoy.
func TestTheGeneratedFilesAreStable(t *testing.T) {
	maze := &plugins.MazeHoneypot{}

	for _, requestPath := range systemFileRequests {
		t.Run(requestPath, func(t *testing.T) {
			first := maze.HandleRequest(newRequest(requestPath))
			second := maze.HandleRequest(newRequest(requestPath))

			assert.Equal(t, first.Body, second.Body, "the content of %s must be stable", requestPath)
		})
	}
}

// TestTheDirectoryListingShowsTheSystemFiles asserts that the listing of a
// directory and its files agree with each other.
//
// A listing of /etc that does not show passwd does not look like a real host.
func TestTheDirectoryListingShowsTheSystemFiles(t *testing.T) {
	maze := &plugins.MazeHoneypot{}

	listing := maze.HandleRequest(newRequest("/etc/"))
	require.Contains(t, listing.Body, "Index of /etc")

	for _, name := range []string{"passwd", "shadow", "hosts", "issue", "os-release"} {
		assert.Contains(t, listing.Body, "href=\"/etc/"+name+"\"",
			"the listing of /etc must show %s", name)
	}

	rootListing := maze.HandleRequest(newRequest("/root/"))
	for _, name := range []string{".bashrc", ".bash_history", ".ssh"} {
		assert.Contains(t, rootListing.Body, "href=\"/root/"+name+"\"",
			"the listing of /root must show %s", name)
	}
}

// TestTheBaitIsUsable asserts that the decoy offers the material that leads
// an attacker to the next step.
//
// The command history of the administrator is the most valuable bait of the
// decoy: it shows what the administrator does, and it invites the attacker
// to try the same commands.
func TestTheBaitIsUsable(t *testing.T) {
	maze := &plugins.MazeHoneypot{}

	history := maze.HandleRequest(newRequest("/root/.bash_history"))
	require.NotEmpty(t, history.Body)

	assert.Contains(t, history.Body, "cat /etc/passwd")
	assert.Contains(t, history.Body, "mysql -u")
	assert.Contains(t, history.Body, "kubectl get pods")

	environ := maze.HandleRequest(newRequest("/proc/self/environ"))
	assert.Contains(t, environ.Body, "DATABASE_URL=")
	assert.Contains(t, environ.Body, "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
		"the credentials of the decoy are the documented example ones")
}

// TestThePrivateKeyProtectsNothing asserts that the key of the decoy is a
// real key that opens nothing.
//
// The key must be accepted by ssh-keygen: a key that does not even parse is
// an obvious fake, and the bait loses its value.
func TestThePrivateKeyProtectsNothing(t *testing.T) {
	maze := &plugins.MazeHoneypot{}

	key := maze.HandleRequest(newRequest("/root/.ssh/id_rsa"))
	require.NotEmpty(t, key.Body)

	assert.Contains(t, key.Body, "-----BEGIN OPENSSH PRIVATE KEY-----")
	assert.Contains(t, key.Body, "-----END OPENSSH PRIVATE KEY-----")

	// The body of the key is generated, not the key of the host.
	hostKey, err := os.ReadFile(os.Getenv("HOME") + "/.ssh/id_rsa")
	if err == nil {
		assert.NotEqual(t, string(hostKey), key.Body, "the answer must not be the key of the host")
	}
}

// TestThePrivateKeyIsAcceptedBySSHKeygen asserts that the key of the decoy
// passes the validation of OpenSSH.
//
// This is the check that separates a bait from a fake: ssh-keygen derives
// the public key of the private one, and refuses the ones it cannot read.
func TestThePrivateKeyIsAcceptedBySSHKeygen(t *testing.T) {
	sshKeygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not available")
	}

	maze := &plugins.MazeHoneypot{}
	key := maze.HandleRequest(newRequest("/root/.ssh/id_rsa")).Body

	directory := t.TempDir()
	path := filepath.Join(directory, "id_rsa")
	require.NoError(t, os.WriteFile(path, []byte(key), 0o600))

	output, err := exec.Command(sshKeygen, "-y", "-f", path).CombinedOutput()
	require.NoError(t, err, "ssh-keygen must accept the key of the decoy: %s", output)

	publicKey := strings.TrimSpace(string(output))
	assert.True(t, strings.HasPrefix(publicKey, "ssh-ed25519 "),
		"the derived public key must be an ed25519 key, got %q", publicKey)

	// The comment must look like the comment of a real key: a decoy that
	// announces itself in the comment gives itself away.
	assert.NotContains(t, strings.ToLower(publicKey), "honey")
	assert.NotContains(t, strings.ToLower(publicKey), "decoy")
}
