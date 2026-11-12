package adversarial

import (
	"net"
	"testing"
	"time"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/internal/protocols/strategies/SSH"
	"github.com/beelzebub-labs/beelzebub/v3/internal/tracer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// baitAccount and baitPassword are the credential the decoy offers in the
// generated /etc/shadow.
//
// The name is an ordinary service account: a decoy that names its bait gives
// itself away. The password is the marker the defender looks for.
const (
	baitAccount  = "svc_backup"
	baitPassword = "Bkp!2023#svc"
)

// TestTheBaitCredentialOpensTheDecoy asserts the whole chain of the bait:
// the credential the decoy publishes is the credential it accepts.
//
// The attacker reads the generated /etc/shadow, cracks the account, and
// tries the password. The attempt must be recorded as a successful login:
// it never happens by accident, and the session that follows is the most
// valuable interaction of the decoy.
func TestTheBaitCredentialOpensTheDecoy(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	require.NoError(t, listener.Close())

	events := make(chan tracer.Event, 32)

	servConf := parser.BeelzebubServiceConfiguration{
		Address:                address,
		Protocol:               "ssh",
		Description:            "OpenSSH",
		ServerName:             "ubuntu",
		ServerVersion:          "OpenSSH_9.6p1 Ubuntu-3ubuntu13",
		PasswordRegex:          "^(root|qwerty|123456|Bkp!2023#svc)$",
		Commands:               []parser.Command{},
		DeadlineTimeoutSeconds: 30,
	}

	strategy := &SSH.SSHStrategy{}
	require.NoError(t, strategy.Init(servConf, tracerFunc(func(event tracer.Event) {
		events <- event
	})))

	client, err := ssh.Dial("tcp", address, &ssh.ClientConfig{
		User:            baitAccount,
		Auth:            []ssh.AuthMethod{ssh.Password(baitPassword)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	require.NoError(t, err, "the bait credential must open the decoy")
	defer client.Close()

	// The login attempt is recorded, with the credential that was used.
	attempt := waitForEvent(t, events, "New SSH Login Attempt")
	assert.Equal(t, baitAccount, attempt.User)
	assert.Equal(t, baitPassword, attempt.Password)
	assert.Equal(t, "Stateless", attempt.Status)

	// The session opens: the attacker keeps interacting, and every command
	// is recorded.
	session, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, session.Shell())

	started := waitForEvent(t, events, "New SSH Terminal Session")
	assert.Equal(t, baitAccount, started.User)
	assert.NotEmpty(t, started.SessionID, "the session must be identified")
}

// waitForEvent waits for an event of the given kind.
func waitForEvent(t *testing.T, events chan tracer.Event, kind string) tracer.Event {
	t.Helper()

	deadline := time.After(5 * time.Second)
	for {
		select {
		case event := <-events:
			if event.Msg == kind {
				return event
			}
		case <-deadline:
			t.Fatalf("the event %q was not recorded", kind)
			return tracer.Event{}
		}
	}
}

// TestTheWrongCredentialIsRefused asserts that the decoy only opens for the
// credentials it publishes.
func TestTheWrongCredentialIsRefused(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	require.NoError(t, listener.Close())

	servConf := parser.BeelzebubServiceConfiguration{
		Address:                address,
		Protocol:               "ssh",
		Description:            "OpenSSH",
		ServerName:             "ubuntu",
		ServerVersion:          "OpenSSH_9.6p1 Ubuntu-3ubuntu13",
		PasswordRegex:          "^(root|qwerty|123456|Bkp!2023#svc)$",
		Commands:               []parser.Command{},
		DeadlineTimeoutSeconds: 30,
	}

	strategy := &SSH.SSHStrategy{}
	require.NoError(t, strategy.Init(servConf, tracerFunc(func(event tracer.Event) {})))

	_, err = ssh.Dial("tcp", address, &ssh.ClientConfig{
		User:            baitAccount,
		Auth:            []ssh.AuthMethod{ssh.Password("not-the-bait")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})

	assert.Error(t, err, "a credential the decoy does not publish must be refused")
}

// tracerFunc is a tracer that forwards the events to a function.
type tracerFunc func(event tracer.Event)

func (f tracerFunc) TraceEvent(event tracer.Event) {
	f(event)
}
