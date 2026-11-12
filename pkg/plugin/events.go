package plugin

import (
	"sync"
)

// Event is the canonical record of a single honeypot interaction.
//
// It lives in the public SDK so that plugins — which are compiled as separate
// Go modules and therefore cannot import the runtime's internal packages — can
// observe every event the runtime emits.
//
// The field set is append-only: new fields are added over time and existing
// ones are never repurposed. Consumers must tolerate unknown fields.
//
// The JSON encoding is unchanged for pre-existing fields: the runtime emits
// these under their Go names, and the newly added identity fields are omitted
// when empty.
type Event struct {
	DateTime   string
	RemoteAddr string
	Protocol   string
	Command    string
	// CommandRaw is a hex-escaped (\xNN) rendering of the exact bytes the
	// client sent. It is populated only when Command's UTF-8 string form would
	// lose data (i.e. the input is not valid UTF-8, as happens with binary
	// protocols), so the original bytes remain recoverable downstream. Empty —
	// and omitted from JSON — for UTF-8 traffic, leaving existing events
	// unchanged.
	CommandRaw      string `json:",omitempty"`
	CommandOutput   string
	Status          string
	Msg             string
	ID              string
	Environ         string
	User            string
	Password        string
	Client          string
	Headers         string
	HeadersMap      map[string][]string
	Cookies         string
	UserAgent       string
	HostHTTPRequest string
	Body            string
	HTTPMethod      string
	RequestURI      string
	Description     string
	SourceIp        string
	SourcePort      string
	TLSServerName   string
	Handler         string
	// Metadata carries protocol-specific values contributed by plugins without
	// coupling the tracer to any wire protocol implementation.
	Metadata map[string]string `json:",omitempty"`

	// --- Identity fields (added in v3; additive only) ---

	// EventID uniquely identifies this single event across the whole runtime.
	// Unlike ID, which keeps its historical per-protocol meaning, EventID is
	// always a fresh unique value.
	EventID string `json:",omitempty"`
	// SessionID groups the events of one logical interaction. For connection
	// oriented protocols it identifies the connection; for connectionless
	// ones (HTTP, MCP) it identifies a rolling session per source.
	SessionID string `json:",omitempty"`
	// ConnID identifies the transport connection the event was observed on.
	// It is empty for protocols without connection semantics.
	ConnID string `json:",omitempty"`
	// Sequence is a monotonically increasing counter scoped to SessionID.
	// It is empty when the event carries no SessionID.
	Sequence int64 `json:",omitempty"`
	// CorrelationKey groups events observed from the same source across
	// sessions and connections — the key used to rebuild an attack chain that
	// spans several connections.
	CorrelationKey string `json:",omitempty"`
}

// EventHandler is invoked once for every event emitted by the runtime.
//
// Handlers run on the runtime's event workers: they must not block and must
// synchronise any shared state they use.
type EventHandler func(Event)

// EventBus delivers runtime events to subscribers.
//
// The runtime implements this interface; plugins consume it through
// RegisterEventHandler or by implementing EventSubscriber.
type EventBus interface {
	// Subscribe registers a handler and returns a function that removes it.
	Subscribe(handler EventHandler) (unsubscribe func())
}

// EventSubscriber is implemented by plugins that want to observe every event
// the runtime emits.
//
// A plugin registered with Register that also implements EventSubscriber is
// wired to the runtime event bus automatically when the runtime starts.
type EventSubscriber interface {
	Plugin
	// OnEvent is called for every emitted event.
	OnEvent(Event)
}

var (
	eventBusMu sync.RWMutex
	eventBus   EventBus
	// pendingHandlers holds handlers registered before the runtime published
	// its bus — plugins register from init(), which runs before main().
	pendingHandlers []EventHandler
)

// RegisterEventHandler subscribes a handler to the runtime event bus.
//
// It is safe to call from a plugin's init(): handlers registered before the
// runtime starts are attached as soon as the bus becomes available.
func RegisterEventHandler(handler EventHandler) {
	if handler == nil {
		return
	}

	eventBusMu.Lock()
	defer eventBusMu.Unlock()

	if eventBus == nil {
		pendingHandlers = append(pendingHandlers, handler)
		return
	}
	eventBus.Subscribe(handler)
}

// SetEventBus publishes the runtime event bus to the plugin registry.
//
// The runtime calls this once during startup. Pending handlers are attached
// and every registered plugin implementing EventSubscriber is wired up.
func SetEventBus(bus EventBus) {
	eventBusMu.Lock()
	eventBus = bus
	handlers := pendingHandlers
	pendingHandlers = nil
	eventBusMu.Unlock()

	if bus == nil {
		return
	}

	for _, handler := range handlers {
		bus.Subscribe(handler)
	}

	for _, p := range allPlugins() {
		subscriber, ok := p.(EventSubscriber)
		if !ok {
			continue
		}
		bus.Subscribe(subscriber.OnEvent)
	}
}
