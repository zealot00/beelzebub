package historystore

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/beelzebub-labs/beelzebub/v3/internal/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHistoryStore(t *testing.T) {
	hs := NewHistoryStore()
	assert.NotNil(t, hs)
	assert.NotNil(t, hs.sessions)
}

func TestAppendBoundedRetainsNewestMessages(t *testing.T) {
	store := NewHistoryStore()
	store.AppendBounded("session", 2,
		plugins.Message{Role: "user", Content: "one"},
		plugins.Message{Role: "assistant", Content: "two"},
		plugins.Message{Role: "user", Content: "three"},
	)
	messages := store.Query("session")
	if len(messages) != 2 || messages[0].Content != "two" || messages[1].Content != "three" {
		t.Fatalf("bounded history = %#v", messages)
	}
}

func TestHasKey(t *testing.T) {
	hs := NewHistoryStore()
	hs.sessions["testKey"] = HistoryEvent{Messages: []plugins.Message{}}
	assert.True(t, hs.HasKey("testKey"))
	assert.False(t, hs.HasKey("nonExistentKey"))
}

func TestQuery(t *testing.T) {
	hs := NewHistoryStore()
	expectedMessages := []plugins.Message{{Role: "user", Content: "Hello"}}
	hs.sessions["testKey"] = HistoryEvent{Messages: expectedMessages}
	actualMessages := hs.Query("testKey")
	assert.Equal(t, expectedMessages, actualMessages)
}

func TestAppend(t *testing.T) {
	hs := NewHistoryStore()
	message1 := plugins.Message{Role: "user", Content: "Hello"}
	message2 := plugins.Message{Role: "assistant", Content: "Hi"}
	hs.Append("testKey", message1)
	assert.Equal(t, []plugins.Message{message1}, hs.sessions["testKey"].Messages)
	hs.Append("testKey", message2)
	assert.Equal(t, []plugins.Message{message1, message2}, hs.sessions["testKey"].Messages)
}

func TestAppendNilSessions(t *testing.T) {
	hs := &HistoryStore{}
	message1 := plugins.Message{Role: "user", Content: "Hello"}
	hs.Append("testKey", message1)
	assert.NotNil(t, hs.sessions)
	assert.Equal(t, []plugins.Message{message1}, hs.sessions["testKey"].Messages)
}

func TestHistoryCleaner(t *testing.T) {
	hs := NewHistoryStore()
	defer hs.Close()
	hs.Append("stale", plugins.Message{Role: "user", Content: "Hello"})
	hs.Append("fresh", plugins.Message{Role: "user", Content: "Hello"})

	// Back-date the stale entry beyond MaxHistoryAge.
	hs.Lock()
	e := hs.sessions["stale"]
	e.LastSeen = time.Now().Add(-MaxHistoryAge * 2)
	hs.sessions["stale"] = e
	hs.Unlock()

	CleanerInterval = 50 * time.Millisecond
	hs.HistoryCleaner()
	time.Sleep(200 * time.Millisecond)

	assert.False(t, hs.HasKey("stale"))
	assert.True(t, hs.HasKey("fresh"))
}

func TestClose(t *testing.T) {
	hs := NewHistoryStore()
	CleanerInterval = 50 * time.Millisecond
	hs.HistoryCleaner()

	// Close should be safe to call multiple times
	hs.Close()
	hs.Close()

	// After Close, the store is still usable for reads/writes
	hs.Append("key", plugins.Message{Role: "user", Content: "test"})
	assert.True(t, hs.HasKey("key"))
}

func TestAppend_Concurrent(t *testing.T) {
	hs := NewHistoryStore()
	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			hs.Append("key", plugins.Message{Role: "user", Content: fmt.Sprintf("msg%d", i)})
		}(i)
	}
	wg.Wait()
	assert.Len(t, hs.Query("key"), goroutines)
}

func TestQuery_MissingKey(t *testing.T) {
	hs := NewHistoryStore()
	assert.Nil(t, hs.Query("nonexistent"))
}

// TestQueryReturnsACopy guards the ownership of the stored messages.
//
// The callers append to the slice they receive. If the store handed out its
// own backing array, two concurrent sessions of the same source would write
// into each other, and the context sent to the model would mix the turns of
// two connections.
func TestQueryReturnsACopy(t *testing.T) {
	store := NewHistoryStore()
	defer store.Close()

	store.Append("session", plugins.Message{Role: "user", Content: "first"})

	queried := store.Query("session")
	require.Len(t, queried, 1)

	queried = append(queried, plugins.Message{Role: "assistant", Content: "appended by the caller"})

	stored := store.Query("session")
	require.Len(t, stored, 1, "the caller must not be able to grow the stored history")
	assert.Equal(t, "first", stored[0].Content)
}

// TestQueryDoesNotAliasTheStoredArray makes sure the copy does not share the
// backing array of the stored slice.
func TestQueryDoesNotAliasTheStoredArray(t *testing.T) {
	store := NewHistoryStore()
	defer store.Close()

	for i := 0; i < 6; i++ {
		store.Append("session", plugins.Message{Role: "user", Content: "m"})
	}

	queried := store.Query("session")
	require.Len(t, queried, 6)

	// Appending to the returned slice must not write into the stored array.
	queried = append(queried, plugins.Message{Role: "assistant", Content: "NEW"})

	stored := store.Query("session")
	require.Len(t, stored, 6)
	for _, message := range stored {
		assert.Equal(t, "m", message.Content)
	}
}

// TestConcurrentSessionsOfTheSameSourceDoNotInterfere exercises the path that
// the SSH and TELNET strategies use: the key of a session is derived from the
// source address and the user name, so two connections of the same source
// share it.
func TestConcurrentSessionsOfTheSameSourceDoNotInterfere(t *testing.T) {
	store := NewHistoryStore()
	defer store.Close()

	const connections = 8
	const turns = 20

	var waitGroup sync.WaitGroup
	waitGroup.Add(connections)

	for i := 0; i < connections; i++ {
		go func() {
			defer waitGroup.Done()
			for turn := 0; turn < turns; turn++ {
				histories := store.Query("SSH10.0.0.5root")
				histories = append(histories, plugins.Message{Role: "user", Content: "command"})
				store.Append("SSH10.0.0.5root", histories[len(histories)-1])
			}
		}()
	}

	waitGroup.Wait()

	stored := store.Query("SSH10.0.0.5root")
	assert.Len(t, stored, connections*turns)
}
