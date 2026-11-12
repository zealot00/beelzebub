package plugins

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// request builds a GET request for the given path.
func request(path string) *http.Request {
	return httptest.NewRequest(http.MethodGet, "http://decoy.internal"+path, nil)
}

// resetInstanceSecret restarts the secret of the instance.
//
// It is used by the tests that need two independent instances.
func resetInstanceSecret() {
	instanceSecretOnce = sync.Once{}
	instanceSecretValue = nil
}

// TestTheInstanceSecretIsUnique asserts that two instances do not derive the
// same material.
//
// Without it, the material of the decoy could be correlated across the
// hosts it runs on, and the attacker could tell that two targets come from
// the same software.
func TestTheInstanceSecretIsUnique(t *testing.T) {
	resetInstanceSecret()
	first := deriveMaterial("label")

	resetInstanceSecret()
	second := deriveMaterial("label")

	assert.NotEqual(t, first, second, "two instances must not derive the same material")
	assert.Len(t, first, 32)
}

// TestTheDerivedMaterialDependsOnTheLabel asserts that two derivations are
// independent.
func TestTheDerivedMaterialDependsOnTheLabel(t *testing.T) {
	resetInstanceSecret()

	assert.NotEqual(t, deriveMaterial("a"), deriveMaterial("b"))
	assert.Equal(t, deriveMaterial("a"), deriveMaterial("a"))
}

// TestThePrivateKeyIsValidAndUnique asserts that the key of the decoy is a
// real key, and that it is not the key of any other instance.
func TestThePrivateKeyIsValidAndUnique(t *testing.T) {
	resetInstanceSecret()

	maze := &MazeHoneypot{}
	first := maze.HandleRequest(request("/root/.ssh/id_rsa")).Body

	resetInstanceSecret()
	second := maze.HandleRequest(request("/root/.ssh/id_rsa")).Body

	require.NotEmpty(t, first)
	assert.Contains(t, first, "-----BEGIN OPENSSH PRIVATE KEY-----")
	assert.Contains(t, first, "-----END OPENSSH PRIVATE KEY-----")

	assert.NotEqual(t, first, second,
		"the key of two instances must differ, otherwise the decoys can be correlated")

	// The key is stable inside an instance.
	third := maze.HandleRequest(request("/root/.ssh/id_rsa")).Body
	assert.Equal(t, second, third, "the key of a path must be stable")
}

// TestTheBaitAccountIsUsable asserts that the bait of the decoy can be
// cracked, and that the defender recognises it.
//
// The name of the account is an ordinary service account: a decoy that names
// its bait tells the attacker what it is.
func TestTheBaitAccountIsUsable(t *testing.T) {
	resetInstanceSecret()

	maze := &MazeHoneypot{}
	shadow := maze.HandleRequest(request("/etc/shadow")).Body
	passwd := maze.HandleRequest(request("/etc/passwd")).Body

	// The account exists on both sides.
	assert.Contains(t, passwd, honeytokenAccount+":x:")

	var hash string
	for _, line := range strings.Split(strings.TrimSpace(shadow), "\n") {
		fields := strings.Split(line, ":")
		require.Len(t, fields, 9)
		if fields[0] == honeytokenAccount {
			hash = fields[1]
		}
	}

	require.NotEmpty(t, hash, "the bait account must be present in the shadow file")

	// The password of the bait is the documented one: the defender
	// recognises the credential wherever it shows up.
	assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(hash), []byte(honeytokenPassword)),
		"the hash of the bait must verify against the documented password")

	// The name of the bait must not give itself away.
	name := strings.ToLower(honeytokenAccount)
	for _, forbidden := range []string{"honey", "honeypot", "decoy", "trap", "bait", "canary"} {
		assert.NotContains(t, name, forbidden,
			"the name of the bait must not announce that the host is a decoy")
	}
}

// TestTheBaitHashIsSalted asserts that the hash of the bait carries a random
// salt, so that two instances never produce the same shadow file.
func TestTheBaitHashIsSalted(t *testing.T) {
	resetInstanceSecret()

	maze := &MazeHoneypot{}
	first := maze.HandleRequest(request("/etc/shadow")).Body

	resetInstanceSecret()
	second := maze.HandleRequest(request("/etc/shadow")).Body

	assert.NotEqual(t, first, second,
		"the shadow file of two instances must differ, the salt is random")

	// Both verify against the same password.
	for _, shadow := range []string{first, second} {
		for _, line := range strings.Split(strings.TrimSpace(shadow), "\n") {
			fields := strings.Split(line, ":")
			if fields[0] != honeytokenAccount {
				continue
			}
			assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(fields[1]), []byte(honeytokenPassword)))
		}
	}
}

// TestOnlyTheBaitHoldsAUsablePassword asserts that every other account of
// the shadow file is locked.
//
// A decoy that offers a crackable hash hands the attacker a credential of a
// real system.
func TestOnlyTheBaitHoldsAUsablePassword(t *testing.T) {
	resetInstanceSecret()

	maze := &MazeHoneypot{}
	shadow := maze.HandleRequest(request("/etc/shadow")).Body

	usable := 0
	for _, line := range strings.Split(strings.TrimSpace(shadow), "\n") {
		fields := strings.Split(line, ":")
		require.Len(t, fields, 9)

		if fields[0] == honeytokenAccount {
			usable++
			continue
		}

		assert.True(t, fields[1] == "*" || fields[1] == "!" || fields[1] == "!!",
			"the password of %q must be locked, got %q", fields[0], fields[1])
	}

	assert.Equal(t, 1, usable, "only the bait account may hold a usable password")
}
