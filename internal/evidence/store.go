// Package evidence stores the payloads the attackers drop on the decoys.
//
// The store is part of the evidence chain: a sample that is captured, hashed
// and written once is a sample that can be compared, shared and replayed.
//
// Two rules govern the implementation:
//
//   - The attacker never influences a path. Every file is named after the
//     SHA-256 of its content, and the name suggested by the attacker is kept
//     as JSON metadata only.
//   - The content is hostile. It is written as an opaque blob, never
//     interpreted, never served and never executed.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/pkg/plugin"
)

// Sample kinds.
const (
	KindHTTPBody   = "http-body"
	KindTCPPayload = "tcp-payload"
	KindCommand    = "command"
)

// Store writes the captured payloads to disk.
//
// It is safe for concurrent use: the events arrive from the runtime workers.
type Store struct {
	root    string
	minSize int
	maxSize int

	mu       sync.Mutex
	seen     map[string]*Sample
	order    []string
	disabled bool
}

// maxKnownSamples bounds the deduplication table.
//
// The table only exists to count the occurrences of a payload. A honeypot
// that runs for months sees a lot of distinct payloads, and the table must
// not grow without bound: the oldest entries are dropped, and a payload that
// comes back is simply written again.
const maxKnownSamples = 4096

// Sample describes one stored payload.
type Sample struct {
	SHA256        string `json:"sha256"`
	Size          int    `json:"size"`
	Kind          string `json:"kind"`
	SuggestedName string `json:"suggestedName,omitempty"`
	Protocol      string `json:"protocol"`
	SourceIp      string `json:"sourceIp"`
	SourcePort    string `json:"sourcePort,omitempty"`
	SessionID     string `json:"sessionId,omitempty"`
	EventID       string `json:"eventId,omitempty"`
	RequestURI    string `json:"requestUri,omitempty"`
	FirstSeen     string `json:"firstSeen"`
	LastSeen      string `json:"lastSeen"`
	Occurrences   int    `json:"occurrences"`
}

// NewStore prepares the sample store.
//
// The root directory is created with restrictive permissions: the samples are
// the payloads of a successful intrusion, they must not be world readable.
func NewStore(conf parser.Evidence) (*Store, error) {
	if !conf.Enabled {
		return &Store{disabled: true}, nil
	}

	if conf.Path == "" {
		return nil, fmt.Errorf("the evidence store is enabled but path is empty")
	}

	root, err := filepath.Abs(conf.Path)
	if err != nil {
		return nil, fmt.Errorf("evidence path: %w", err)
	}

	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("evidence directory: %w", err)
	}

	// MkdirAll only applies the mode to the directories it creates: an
	// existing directory keeps its permissions. The samples are the payloads
	// of a successful intrusion, so the directory is tightened explicitly.
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, fmt.Errorf("evidence directory permissions: %w", err)
	}

	minSize := conf.MinSizeBytes
	if minSize <= 0 {
		minSize = 64
	}
	maxSize := conf.MaxSizeBytes
	if maxSize <= 0 {
		maxSize = 1 << 20
	}

	return &Store{
		root:    root,
		minSize: minSize,
		maxSize: maxSize,
		seen:    make(map[string]*Sample),
	}, nil
}

// Handle processes one event. It implements the event handler of the runtime.
func (s *Store) Handle(event plugin.Event) {
	if s == nil || s.disabled {
		return
	}

	payload, kind, suggestedName := extractPayload(event)
	if len(payload) < s.minSize {
		return
	}
	if len(payload) > s.maxSize {
		payload = payload[:s.maxSize]
	}

	if err := s.store(payload, kind, suggestedName, event); err != nil {
		// The capture must never interrupt the honeypot.
		return
	}
}

// store writes the payload and its metadata.
//
// The file name is derived from the digest only: the name suggested by the
// attacker stays in the metadata.
func (s *Store) store(payload []byte, kind, suggestedName string, event plugin.Event) error {
	digest := sha256.Sum256(payload)
	sum := hex.EncodeToString(digest[:])

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, known := s.seen[sum]
	if known {
		existing.Occurrences++
		existing.LastSeen = event.DateTime
		return s.writeMetadata(existing)
	}

	sample := &Sample{
		SHA256:        sum,
		Size:          len(payload),
		Kind:          kind,
		SuggestedName: suggestedName,
		Protocol:      event.Protocol,
		SourceIp:      event.SourceIp,
		SourcePort:    event.SourcePort,
		SessionID:     event.SessionID,
		EventID:       event.EventID,
		RequestURI:    event.RequestURI,
		FirstSeen:     event.DateTime,
		LastSeen:      event.DateTime,
		Occurrences:   1,
	}

	if err := s.writePayload(sum, payload); err != nil {
		return err
	}
	if err := s.writeMetadata(sample); err != nil {
		return err
	}

	s.seen[sum] = sample
	s.order = append(s.order, sum)

	// Bound the table: the oldest entries are dropped first.
	for len(s.order) > maxKnownSamples {
		oldest := s.order[0]
		s.order = s.order[1:]
		delete(s.seen, oldest)
	}

	return nil
}

// writePayload writes the blob of the sample.
func (s *Store) writePayload(sum string, payload []byte) error {
	directory := filepath.Join(s.root, sum[:2])
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}

	// Write to a temporary file and rename it, so that a reader never sees a
	// partially written sample.
	temporary, err := os.CreateTemp(directory, ".sample-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()

	defer func() {
		_ = os.Remove(temporaryName)
	}()

	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}

	return os.Rename(temporaryName, filepath.Join(directory, sum+".bin"))
}

// writeMetadata writes the metadata sidecar of the sample.
func (s *Store) writeMetadata(sample *Sample) error {
	directory := filepath.Join(s.root, sample.SHA256[:2])
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}

	encoded, err := json.MarshalIndent(sample, "", "  ")
	if err != nil {
		return err
	}

	temporary, err := os.CreateTemp(directory, ".meta-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()

	defer func() {
		_ = os.Remove(temporaryName)
	}()

	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}

	return os.Rename(temporaryName, filepath.Join(directory, sample.SHA256+".json"))
}

// Count returns the number of distinct samples stored.
func (s *Store) Count() int {
	if s == nil || s.disabled {
		return 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}

// extractPayload returns the candidate payload carried by the event.
func extractPayload(event plugin.Event) ([]byte, string, string) {
	switch event.Protocol {
	case "HTTP":
		if event.Body == "" {
			return nil, "", ""
		}
		return []byte(event.Body), KindHTTPBody, suggestedNameFromURI(event.RequestURI)
	case "TCP":
		// The exact frame when the protocol could provide it: the string
		// fields are a lossy re-encoding of the binary protocols.
		if len(event.Payload) > 0 {
			return event.Payload, KindTCPPayload, ""
		}
		if event.CommandRaw != "" {
			return decodeHexEscape(event.CommandRaw), KindTCPPayload, ""
		}
		if event.Command == "" {
			return nil, "", ""
		}
		return []byte(event.Command), KindTCPPayload, ""
	case "SSH", "TELNET":
		if event.Command == "" {
			return nil, "", ""
		}
		return []byte(event.Command), KindCommand, ""
	default:
		return nil, "", ""
	}
}

// decodeHexEscape reverses the \xNN escaping used by the TCP strategy.
//
// The escaping emits every non printable byte, and the backslash itself, as
// \xNN, so the original byte sequence is recovered exactly.
func decodeHexEscape(encoded string) []byte {
	decoded := make([]byte, 0, len(encoded))

	for i := 0; i < len(encoded); i++ {
		if encoded[i] == '\\' && i+3 < len(encoded) && encoded[i+1] == 'x' {
			high, highOK := hexValue(encoded[i+2])
			low, lowOK := hexValue(encoded[i+3])
			if highOK && lowOK {
				decoded = append(decoded, high<<4|low)
				i += 3
				continue
			}
		}
		decoded = append(decoded, encoded[i])
	}

	return decoded
}

// hexValue converts a hexadecimal digit.
func hexValue(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// suggestedNameFromURI extracts the file name the attacker tried to reach.
//
// The value is only a hint: it is stored as metadata and never used to build
// a path.
func suggestedNameFromURI(requestURI string) string {
	if requestURI == "" {
		return ""
	}

	trimmed := requestURI
	if index := strings.IndexAny(trimmed, "?#"); index >= 0 {
		trimmed = trimmed[:index]
	}

	trimmed = strings.TrimRight(trimmed, "/")
	index := strings.LastIndex(trimmed, "/")
	if index < 0 {
		return ""
	}

	name := trimmed[index+1:]
	if len(name) > 128 {
		name = name[:128]
	}

	// The hint is displayed and stored as data: strip the characters that
	// would make a log or a terminal misbehave.
	return sanitizeSuggestedName(name)
}

// sanitizeSuggestedName removes the control characters from a name.
func sanitizeSuggestedName(name string) string {
	var builder strings.Builder
	builder.Grow(len(name))

	for _, r := range name {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			builder.WriteRune(' ')
		case r < 0x20 || r == 0x7f:
			// dropped
		default:
			builder.WriteRune(r)
		}
	}

	return builder.String()
}
