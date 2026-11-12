// Package tracer is responsible for tracing the events that occur in the honeypots
package tracer

import (
	"sync"
	"time"

	"github.com/beelzebub-labs/beelzebub/v3/pkg/plugin"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	log "github.com/sirupsen/logrus"
)

const Workers = 5

// Event is the canonical interaction record.
//
// The definition lives in the public plugin SDK so that external plugins —
// which cannot import this package — can observe every emitted event. The
// alias keeps the historical internal/tracer.Event usage working unchanged.
type Event = plugin.Event

type (
	Protocol int
	Status   int
)

const (
	HTTP Protocol = iota
	SSH
	TCP
	MCP
	TELNET
)

func (protocol Protocol) String() string {
	return [...]string{"HTTP", "SSH", "TCP", "MCP", "TELNET"}[protocol]
}

// ProtocolFromString converts a lowercase protocol name to its Protocol constant.
func ProtocolFromString(s string) (Protocol, bool) {
	switch s {
	case "http":
		return HTTP, true
	case "ssh":
		return SSH, true
	case "tcp":
		return TCP, true
	case "mcp":
		return MCP, true
	case "telnet":
		return TELNET, true
	default:
		return 0, false
	}
}

const (
	Start Status = iota
	End
	Stateless
	Interaction
)

func (status Status) String() string {
	return [...]string{"Start", "End", "Stateless", "Interaction"}[status]
}

// Strategy is a sink that receives every emitted event.
//
// Several strategies can be active at the same time: the runtime composes
// them into a fan-out so that logging, RabbitMQ, syslog and the Beelzebub
// Cloud all receive the same events instead of overriding each other.
type Strategy func(event Event)

type Tracer interface {
	TraceEvent(event Event)
}

type tracer struct {
	strategies []Strategy

	// subscribers holds plugin-registered event handlers, keyed by a stable
	// identifier so that they can be detached again.
	subscribers     map[uint64]plugin.EventHandler
	subscriberID    uint64
	subscriberMutex sync.RWMutex

	eventsChan        chan Event
	eventsTotal       prometheus.Counter
	eventsSSHTotal    prometheus.Counter
	eventsTCPTotal    prometheus.Counter
	eventsHTTPTotal   prometheus.Counter
	eventsMCPTotal    prometheus.Counter
	eventsTelnetTotal prometheus.Counter

	strategyMutex sync.RWMutex

	// sequenceMu guards sequences, the per-session event counter.
	sequenceMu sync.Mutex
	sequences  map[string]int64
}

var lock = &sync.Mutex{}
var singleton *tracer

func GetInstance(defaultStrategy Strategy) *tracer {
	if singleton == nil {
		lock.Lock()
		defer lock.Unlock()
		// This is to prevent expensive lock operations every time the GetInstance method is called
		if singleton == nil {
			instance := &tracer{
				strategies:  filterStrategies([]Strategy{defaultStrategy}),
				eventsChan:  make(chan Event, Workers),
				sequences:   make(map[string]int64),
				subscribers: make(map[uint64]plugin.EventHandler),
				eventsTotal: promauto.NewCounter(prometheus.CounterOpts{
					Namespace: "beelzebub",
					Name:      "events_total",
					Help:      "The total number of events",
				}),
				eventsSSHTotal: promauto.NewCounter(prometheus.CounterOpts{
					Namespace: "beelzebub",
					Name:      "ssh_events_total",
					Help:      "The total number of SSH events",
				}),
				eventsTCPTotal: promauto.NewCounter(prometheus.CounterOpts{
					Namespace: "beelzebub",
					Name:      "tcp_events_total",
					Help:      "The total number of TCP events",
				}),
				eventsHTTPTotal: promauto.NewCounter(prometheus.CounterOpts{
					Namespace: "beelzebub",
					Name:      "http_events_total",
					Help:      "The total number of HTTP events",
				}),
				eventsMCPTotal: promauto.NewCounter(prometheus.CounterOpts{
					Namespace: "beelzebub",
					Name:      "mcp_events_total",
					Help:      "The total number of MCP events",
				}),
				eventsTelnetTotal: promauto.NewCounter(prometheus.CounterOpts{
					Namespace: "beelzebub",
					Name:      "telnet_events_total",
					Help:      "The total number of TELNET events",
				}),
			}

			for i := 0; i < Workers; i++ {
				go func(i int) {
					log.Debug("Trace worker: ", i)
					for event := range instance.eventsChan {
						instance.dispatch(event)
					}
				}(i)
			}

			singleton = instance
		}
	} else if defaultStrategy != nil && len(singleton.strategies) == 0 {
		// The singleton already exists but has no sink attached — adopt the
		// default so that a late GetInstance call never leaves the runtime
		// without a consumer.
		singleton.SetStrategies([]Strategy{defaultStrategy})
	}

	return singleton
}

// filterStrategies drops nil sinks so that a disabled output can be wired in
// without guarding every dispatch site.
func filterStrategies(strategies []Strategy) []Strategy {
	filtered := make([]Strategy, 0, len(strategies))
	for _, strategy := range strategies {
		if strategy != nil {
			filtered = append(filtered, strategy)
		}
	}
	return filtered
}

// SetStrategy replaces every active sink.
//
// It keeps the historical single-sink behaviour: the runtime uses
// SetStrategies to install a fan-out, while callers that want to intercept or
// replace the pipeline entirely keep using this method.
func (tracer *tracer) SetStrategy(strategy Strategy) {
	tracer.SetStrategies([]Strategy{strategy})
}

// SetStrategies replaces the active sinks with the given list.
func (tracer *tracer) SetStrategies(strategies []Strategy) {
	tracer.strategyMutex.Lock()
	defer tracer.strategyMutex.Unlock()
	tracer.strategies = filterStrategies(strategies)
}

// AddStrategy appends a sink to the active list.
//
// Sinks receive events in registration order; a failing sink must not stop
// the ones registered after it.
func (tracer *tracer) AddStrategy(strategy Strategy) {
	if strategy == nil {
		return
	}
	tracer.strategyMutex.Lock()
	defer tracer.strategyMutex.Unlock()
	tracer.strategies = append(tracer.strategies, strategy)
}

// GetStrategy returns the first active sink.
//
// It is kept for callers that need to wrap the existing pipeline; the
// returned function is the sink itself, not a fan-out of all sinks.
func (tracer *tracer) GetStrategy() Strategy {
	tracer.strategyMutex.RLock()
	defer tracer.strategyMutex.RUnlock()
	if len(tracer.strategies) == 0 {
		return nil
	}
	return tracer.strategies[0]
}

// Subscribe implements plugin.EventBus: it attaches a handler to the event
// pipeline and returns a function that detaches it again.
func (tracer *tracer) Subscribe(handler plugin.EventHandler) func() {
	if handler == nil {
		return func() {}
	}

	tracer.subscriberMutex.Lock()
	tracer.subscriberID++
	id := tracer.subscriberID
	tracer.subscribers[id] = handler
	tracer.subscriberMutex.Unlock()

	return func() {
		tracer.subscriberMutex.Lock()
		defer tracer.subscriberMutex.Unlock()
		delete(tracer.subscribers, id)
	}
}

// dispatch delivers an event to every active sink and plugin subscriber.
//
// Every consumer receives its own copy of the mutable parts of the event:
// the metadata map and the header map. Without this, a consumer that keeps a
// reference — or that mutates it — would corrupt the evidence seen by the
// others, and the recorded interaction would no longer match what happened.
func (tracer *tracer) dispatch(event Event) {
	tracer.strategyMutex.RLock()
	sinks := make([]Strategy, len(tracer.strategies))
	copy(sinks, tracer.strategies)
	tracer.strategyMutex.RUnlock()

	tracer.subscriberMutex.RLock()
	handlers := make([]plugin.EventHandler, 0, len(tracer.subscribers))
	for _, handler := range tracer.subscribers {
		handlers = append(handlers, handler)
	}
	tracer.subscriberMutex.RUnlock()

	for _, sink := range sinks {
		if sink == nil {
			continue
		}
		sink(cloneEvent(event))
	}

	for _, handler := range handlers {
		handler(cloneEvent(event))
	}
}

// cloneEvent detaches the mutable fields of an event.
//
// The scalar fields are copied by the assignment. The maps are copied
// explicitly, including the value slices of the header map, so that the
// returned event never shares a mutable structure with the original.
func cloneEvent(event Event) Event {
	clone := event

	if event.Metadata != nil {
		clone.Metadata = make(map[string]string, len(event.Metadata))
		for key, value := range event.Metadata {
			clone.Metadata[key] = value
		}
	}

	if event.HeadersMap != nil {
		clone.HeadersMap = make(map[string][]string, len(event.HeadersMap))
		for key, values := range event.HeadersMap {
			copied := make([]string, len(values))
			copy(copied, values)
			clone.HeadersMap[key] = copied
		}
	}

	if event.Payload != nil {
		clone.Payload = make([]byte, len(event.Payload))
		copy(clone.Payload, event.Payload)
	}

	return clone
}

func (tracer *tracer) TraceEvent(event Event) {
	event.DateTime = time.Now().UTC().Format(time.RFC3339)
	if event.EventID == "" {
		event.EventID = uuid.New().String()
	}
	if event.SessionID != "" {
		event.Sequence = tracer.nextSequence(event.SessionID)
	}

	tracer.eventsChan <- cloneEvent(event)

	tracer.updatePrometheusCounters(event.Protocol)
}

// nextSequence returns the next per-session event counter.
func (tracer *tracer) nextSequence(sessionID string) int64 {
	tracer.sequenceMu.Lock()
	defer tracer.sequenceMu.Unlock()
	tracer.sequences[sessionID]++
	return tracer.sequences[sessionID]
}

func (tracer *tracer) updatePrometheusCounters(protocol string) {
	switch protocol {
	case HTTP.String():
		tracer.eventsHTTPTotal.Inc()
	case SSH.String():
		tracer.eventsSSHTotal.Inc()
	case TCP.String():
		tracer.eventsTCPTotal.Inc()
	case MCP.String():
		tracer.eventsMCPTotal.Inc()
	case TELNET.String():
		tracer.eventsTelnetTotal.Inc()
	}
	tracer.eventsTotal.Inc()
}
