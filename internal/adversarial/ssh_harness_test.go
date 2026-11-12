package adversarial

import (
	"net"
	"regexp"
	"testing"
	"time"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/internal/protocols/strategies/SSH"
	"github.com/beelzebub-labs/beelzebub/v3/internal/tracer"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// freeAddress returns an address that is free at the time of the call.
func freeAddress(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	require.NoError(t, listener.Close())

	return address
}

// startSSHDecoy starts the SSH decoy and connects to it.
//
// The address is obtained by binding and releasing a port, which is a race:
// another process can take it in between, and the connection then reaches
// something else. The connection is therefore retried with a fresh address.
//
// It returns the client and the channel the events of the decoy are
// published on.
func startSSHDecoy(t *testing.T, servConf parser.BeelzebubServiceConfiguration, config *ssh.ClientConfig) (*ssh.Client, chan tracer.Event) {
	t.Helper()

	events := make(chan tracer.Event, 256)

	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		servConf.Address = freeAddress(t)

		strategy := &SSH.SSHStrategy{}
		require.NoError(t, strategy.Init(servConf, tracerFunc(func(event tracer.Event) {
			events <- event
		})))

		client, err := ssh.Dial("tcp", servConf.Address, config)
		if err == nil {
			return client, events
		}

		lastErr = err
		time.Sleep(150 * time.Millisecond)
	}

	t.Fatalf("the decoy could not be reached: %v", lastErr)

	return nil, nil
}

// waitForEvent waits for an event of the given kind.
//
// The timeout is generous: the suite runs under the race detector, and the
// machine may be loaded.
func waitForEvent(t *testing.T, events chan tracer.Event, kind string) tracer.Event {
	t.Helper()

	deadline := time.After(15 * time.Second)
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

// mustRegex compiles a pattern, or fails.
func mustRegex(pattern string) *regexp.Regexp {
	return regexp.MustCompile(pattern)
}
