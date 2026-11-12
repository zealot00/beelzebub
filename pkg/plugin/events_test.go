package plugin

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeBus is a minimal EventBus used to capture the subscriptions.
type fakeBus struct {
	mu       sync.Mutex
	handlers []EventHandler
}

func (b *fakeBus) Subscribe(handler EventHandler) func() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.handlers = append(b.handlers, handler)
	return func() {}
}

func (b *fakeBus) emit(event Event) {
	b.mu.Lock()
	handlers := make([]EventHandler, len(b.handlers))
	copy(handlers, b.handlers)
	b.mu.Unlock()

	for _, handler := range handlers {
		handler(event)
	}
}

// subscriberPlugin is a plugin that observes every event.
type subscriberPlugin struct {
	mu     sync.Mutex
	events []Event
}

func (p *subscriberPlugin) Metadata() Metadata {
	return Metadata{Name: "event-subscriber-test", Version: "1.0.0"}
}

func (p *subscriberPlugin) OnEvent(event Event) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, event)
}

func TestRegisterEventHandlerBeforeTheBusExists(t *testing.T) {
	eventBusMu.Lock()
	eventBus = nil
	pendingHandlers = nil
	eventBusMu.Unlock()

	var mu sync.Mutex
	var received []Event

	RegisterEventHandler(func(event Event) {
		mu.Lock()
		defer mu.Unlock()
		received = append(received, event)
	})

	// The handler is pending until the runtime publishes its bus.
	eventBusMu.Lock()
	assert.Len(t, pendingHandlers, 1)
	eventBusMu.Unlock()

	bus := &fakeBus{}
	SetEventBus(bus)

	eventBusMu.Lock()
	assert.Empty(t, pendingHandlers, "the pending handlers must be attached")
	eventBusMu.Unlock()

	bus.emit(Event{EventID: "one"})

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, received, 1)
	assert.Equal(t, "one", received[0].EventID)
}

func TestRegisterEventHandlerAfterTheBusExists(t *testing.T) {
	bus := &fakeBus{}
	SetEventBus(bus)

	var mu sync.Mutex
	var count int

	RegisterEventHandler(func(event Event) {
		mu.Lock()
		defer mu.Unlock()
		count++
	})

	bus.emit(Event{})

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 1, count)
}

func TestEventSubscriberPluginsAreWiredAutomatically(t *testing.T) {
	subscriber := &subscriberPlugin{}
	Register(subscriber)

	bus := &fakeBus{}
	SetEventBus(bus)

	bus.emit(Event{EventID: "from-bus"})

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		subscriber.mu.Lock()
		got := len(subscriber.events)
		subscriber.mu.Unlock()
		if got > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	subscriber.mu.Lock()
	defer subscriber.mu.Unlock()
	require.Len(t, subscriber.events, 1)
	assert.Equal(t, "from-bus", subscriber.events[0].EventID)
}

func TestRegisterEventHandlerIgnoresNil(t *testing.T) {
	bus := &fakeBus{}
	SetEventBus(bus)

	bus.mu.Lock()
	before := len(bus.handlers)
	bus.mu.Unlock()

	assert.NotPanics(t, func() { RegisterEventHandler(nil) })

	bus.mu.Lock()
	defer bus.mu.Unlock()
	assert.Len(t, bus.handlers, before, "a nil handler must not be subscribed")
}
