package tracer

import (
	"sync"
	"testing"
	"time"

	"github.com/beelzebub-labs/beelzebub/v3/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// waitForEvents waits until the expected number of events has been collected.
func waitForEvents(t *testing.T, counter *int32, mu *sync.Mutex, expected int32) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := *counter
		mu.Unlock()
		if got >= expected {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	got := *counter
	mu.Unlock()
	require.GreaterOrEqual(t, got, expected, "the expected events were not delivered")
}

func TestDispatchDeliversToEverySink(t *testing.T) {
	tr := GetInstance(nil)

	var mu sync.Mutex
	var first, second int32

	tr.SetStrategies([]Strategy{
		func(event Event) {
			mu.Lock()
			first++
			mu.Unlock()
		},
		func(event Event) {
			mu.Lock()
			second++
			mu.Unlock()
		},
	})
	defer tr.SetStrategies(nil)

	tr.TraceEvent(Event{ID: "fanout-1"})

	waitForEvents(t, &first, &mu, 1)
	waitForEvents(t, &second, &mu, 1)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, int32(1), first)
	assert.Equal(t, int32(1), second)
}

func TestAddStrategyAppendsToTheExistingSinks(t *testing.T) {
	tr := GetInstance(nil)

	var mu sync.Mutex
	var count int32

	tr.SetStrategies([]Strategy{func(event Event) {
		mu.Lock()
		count++
		mu.Unlock()
	}})
	defer tr.SetStrategies(nil)

	tr.AddStrategy(func(event Event) {
		mu.Lock()
		count++
		mu.Unlock()
	})

	tr.TraceEvent(Event{ID: "append-1"})

	waitForEvents(t, &count, &mu, 2)
}

func TestSubscribeReceivesEventsAndCanBeRemoved(t *testing.T) {
	tr := GetInstance(nil)
	tr.SetStrategies(nil)
	defer tr.SetStrategies(nil)

	var mu sync.Mutex
	var count int32

	unsubscribe := tr.Subscribe(func(event plugin.Event) {
		mu.Lock()
		count++
		mu.Unlock()
	})

	tr.TraceEvent(Event{ID: "sub-1"})
	waitForEvents(t, &count, &mu, 1)

	unsubscribe()

	tr.TraceEvent(Event{ID: "sub-2"})
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, int32(1), count, "the unsubscribed handler must not receive further events")
}

func TestTraceEventFillsEventIDAndSequence(t *testing.T) {
	tr := GetInstance(nil)

	var mu sync.Mutex
	var received []Event

	tr.SetStrategies([]Strategy{func(event Event) {
		mu.Lock()
		received = append(received, event)
		mu.Unlock()
	}})
	defer tr.SetStrategies(nil)

	tr.TraceEvent(Event{ID: "seq-1", SessionID: "session-a"})
	tr.TraceEvent(Event{ID: "seq-2", SessionID: "session-a"})
	tr.TraceEvent(Event{ID: "seq-3", SessionID: "session-b"})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := len(received)
		mu.Unlock()
		if got >= 3 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, received, 3)

	for _, event := range received {
		assert.NotEmpty(t, event.EventID, "the event id must be generated")
		assert.NotEmpty(t, event.DateTime)
	}

	// The sinks are fed by concurrent workers, so the delivery order is not
	// guaranteed: the sequence is what orders the events of a session.
	sequences := map[string][]int64{}
	eventIDs := map[string]bool{}
	for _, event := range received {
		sequences[event.SessionID] = append(sequences[event.SessionID], event.Sequence)
		eventIDs[event.EventID] = true
	}

	assert.ElementsMatch(t, []int64{1, 2}, sequences["session-a"])
	assert.ElementsMatch(t, []int64{1}, sequences["session-b"])

	// The generated identifiers are unique.
	assert.Len(t, eventIDs, 3)
}

func TestTraceEventKeepsAnExplicitEventID(t *testing.T) {
	tr := GetInstance(nil)

	var mu sync.Mutex
	var received Event

	tr.SetStrategies([]Strategy{func(event Event) {
		mu.Lock()
		received = event
		mu.Unlock()
	}})
	defer tr.SetStrategies(nil)

	tr.TraceEvent(Event{EventID: "explicit-id"})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := received
		mu.Unlock()
		if got.EventID != "" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, "explicit-id", received.EventID)
}

func TestSetStrategyReplacesThePreviousSinks(t *testing.T) {
	tr := GetInstance(nil)

	var mu sync.Mutex
	var first, second int32

	tr.SetStrategies([]Strategy{func(event Event) {
		mu.Lock()
		first++
		mu.Unlock()
	}})
	tr.SetStrategy(func(event Event) {
		mu.Lock()
		second++
		mu.Unlock()
	})
	defer tr.SetStrategies(nil)

	tr.TraceEvent(Event{ID: "replace-1"})

	waitForEvents(t, &second, &mu, 1)
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, int32(0), first, "the replaced sink must not receive events anymore")
	assert.Equal(t, int32(1), second)
}

// TestEveryConsumerGetsItsOwnCopyOfTheMutableFields is the copy safety
// guarantee: a consumer that mutates the metadata of an event it received
// must not change what the other consumers see.
//
// Without the copy, the evidence recorded by one output could be altered by
// another, and the interaction would no longer match what happened.
func TestEveryConsumerGetsItsOwnCopyOfTheMutableFields(t *testing.T) {
	tr := GetInstance(nil)

	var mu sync.Mutex
	var first, second Event

	tr.SetStrategies([]Strategy{
		func(event Event) {
			// The first consumer tampers with the metadata it receives.
			if event.Metadata != nil {
				event.Metadata["tampered"] = "true"
			}
			mu.Lock()
			first = event
			mu.Unlock()
		},
		func(event Event) {
			mu.Lock()
			second = event
			mu.Unlock()
		},
	})
	defer tr.SetStrategies(nil)

	tr.TraceEvent(Event{ID: "copy-1", Metadata: map[string]string{"original": "value"}})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := first.ID != "" && second.ID != ""
		mu.Unlock()
		if got {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, first.ID)
	require.NotEmpty(t, second.ID)

	assert.Equal(t, "true", first.Metadata["tampered"], "the first consumer sees its own change")
	assert.NotContains(t, second.Metadata, "tampered", "the second consumer must not see it")
	assert.Equal(t, "value", second.Metadata["original"])
}
