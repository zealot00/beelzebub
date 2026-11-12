package adversarial

import (
	"testing"
	"time"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/internal/protocols/strategies/SSH"
	"github.com/beelzebub-labs/beelzebub/v3/internal/protocols/strategies/TELNET"
	"github.com/beelzebub-labs/beelzebub/v3/internal/tracer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// TestEverySSHCommandIsRecorded asserts that the decoy keeps the commands it
// does not know how to answer.
//
// A configuration without a catch-all rule used to drop them silently. The
// commands an attacker types that the decoy did not anticipate are the
// reconnaissance ones, and they are the ones worth keeping.
func TestEverySSHCommandIsRecorded(t *testing.T) {
	address := freeAddress(t)

	events := make(chan tracer.Event, 64)

	servConf := parser.BeelzebubServiceConfiguration{
		Address:                address,
		Protocol:               "ssh",
		Description:            "SSH interactive",
		ServerName:             "ubuntu",
		ServerVersion:          "OpenSSH_9.6p1 Ubuntu-3ubuntu13",
		PasswordRegex:          "^(root|123456)$",
		DeadlineTimeoutSeconds: 30,
		// No catch-all: the decoy only knows how to answer one command.
		Commands: []parser.Command{
			{Regex: mustRegex("^pwd$"), Handler: "/home/", Name: "pwd"},
		},
	}

	strategy := &SSH.SSHStrategy{}
	require.NoError(t, strategy.Init(servConf, tracerFunc(func(event tracer.Event) {
		events <- event
	})))

	client, err := ssh.Dial("tcp", address, &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.Password("123456")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	require.NoError(t, err)
	defer client.Close()

	session, err := client.NewSession()
	require.NoError(t, err)

	// The pipes must be taken before the shell starts.
	stdin, err := session.StdinPipe()
	require.NoError(t, err)

	_, err = session.StdoutPipe()
	require.NoError(t, err)

	require.NoError(t, session.Shell())

	_, err = stdin.Write([]byte("pwd\n"))
	require.NoError(t, err)
	_, err = stdin.Write([]byte("whoami\n"))
	require.NoError(t, err)
	_, err = stdin.Write([]byte("cat /etc/shadow\n"))
	require.NoError(t, err)
	time.Sleep(300 * time.Millisecond)

	recorded := map[string]bool{}
	deadline := time.After(3 * time.Second)
	for len(recorded) < 3 {
		select {
		case event := <-events:
			if event.Msg == "SSH Terminal Session Interaction" {
				recorded[event.Command] = true
			}
		case <-deadline:
			t.Fatalf("the interactions must be recorded, got %v", recorded)
		}
	}

	assert.True(t, recorded["whoami"], "a command that matches no rule must be recorded")
	assert.True(t, recorded["cat /etc/shadow"], "a command that matches no rule must be recorded")
	assert.True(t, recorded["pwd"], "a command that matches a rule must be recorded")
}

// ensure the TELNET strategy is linked in: the same completeness property
// is asserted for it in its own package.
var _ = TELNET.TelnetStrategy{}
