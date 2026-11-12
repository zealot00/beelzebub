package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestStore(t *testing.T) (*Store, string) {
	t.Helper()

	root := filepath.Join(t.TempDir(), "samples")
	store, err := NewStore(parser.Evidence{
		Enabled:      true,
		Path:         root,
		MinSizeBytes: 16,
		MaxSizeBytes: 1 << 20,
	})
	require.NoError(t, err)

	return store, root
}

func TestStoreKeepsTheExactBytes(t *testing.T) {
	store, root := newTestStore(t)

	// A payload that is valid UTF-8 but is not text: the string fields of the
	// event would re-encode it, the payload channel keeps it intact.
	payload := []byte{0xC3, 0xBF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}

	store.Handle(plugin.Event{
		Protocol: "TCP",
		Payload:  payload,
		Command:  "Ã¿",
		EventID:  "event-1",
	})

	require.Equal(t, 1, store.Count())

	stored := readStoredSample(t, root)
	assert.Equal(t, payload, stored, "the stored sample must be the exact bytes of the attacker payload")
}

func TestStoreDeduplicatesByDigest(t *testing.T) {
	store, root := newTestStore(t)

	payload := []byte(strings.Repeat("A", 64))

	for i := 0; i < 3; i++ {
		store.Handle(plugin.Event{Protocol: "HTTP", Body: string(payload), EventID: "event"})
	}

	assert.Equal(t, 1, store.Count(), "the same payload must be stored once")

	entries := listSamples(t, root)
	require.Len(t, entries, 1)
	assert.Equal(t, 3, entries[0].Occurrences)
	assert.Equal(t, 64, entries[0].Size)
}

func TestStoreIgnoresSmallPayloads(t *testing.T) {
	store, root := newTestStore(t)

	store.Handle(plugin.Event{Protocol: "HTTP", Body: "GET /"})

	assert.Equal(t, 0, store.Count())
	entries := listSamples(t, root)
	assert.Empty(t, entries)
}

func TestStoreNeverUsesTheAttackerNameInAPath(t *testing.T) {
	store, root := newTestStore(t)

	// The attacker asks for a path that tries to escape the store.
	store.Handle(plugin.Event{
		Protocol:   "HTTP",
		Body:       strings.Repeat("B", 128),
		RequestURI: "/../../../../etc/passwd",
	})

	entries := listSamples(t, root)
	require.Len(t, entries, 1)

	// The name is kept as a hint in the metadata...
	assert.Equal(t, "passwd", entries[0].SuggestedName)

	// ...and the file lives under the digest directory.
	files, err := os.ReadDir(filepath.Join(root, entries[0].SHA256[:2]))
	require.NoError(t, err)
	for _, file := range files {
		assert.True(t, strings.HasPrefix(file.Name(), entries[0].SHA256),
			"the file name must be derived from the digest only, got %q", file.Name())
	}
}

func TestStoreKeepsThePermissions(t *testing.T) {
	store, root := newTestStore(t)

	store.Handle(plugin.Event{Protocol: "HTTP", Body: strings.Repeat("C", 128)})

	entries := listSamples(t, root)
	require.Len(t, entries, 1)

	directory := filepath.Join(root, entries[0].SHA256[:2])
	info, err := os.Stat(directory)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())

	payload, err := os.ReadFile(filepath.Join(directory, entries[0].SHA256+".bin"))
	require.NoError(t, err)
	assert.NotEmpty(t, payload)

	payloadInfo, err := os.Stat(filepath.Join(directory, entries[0].SHA256+".bin"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), payloadInfo.Mode().Perm())
}

func TestStoreExtractsTheHTTPBody(t *testing.T) {
	store, _ := newTestStore(t)

	body := strings.Repeat("<?php system($_GET['c']); ?>", 8)
	store.Handle(plugin.Event{Protocol: "HTTP", Body: body, SourceIp: "10.0.0.5", RequestURI: "/shell.php"})

	entries := listSamples(t, mustRoot(t, store))
	require.Len(t, entries, 1)
	assert.Equal(t, KindHTTPBody, entries[0].Kind)
	assert.Equal(t, "10.0.0.5", entries[0].SourceIp)
	assert.Equal(t, "/shell.php", entries[0].RequestURI)
	assert.Equal(t, "shell.php", entries[0].SuggestedName)
}

func TestStoreIsDisabledByDefault(t *testing.T) {
	store, err := NewStore(parser.Evidence{Enabled: false})
	require.NoError(t, err)

	store.Handle(plugin.Event{Protocol: "HTTP", Body: strings.Repeat("D", 128)})

	assert.Equal(t, 0, store.Count())
}

func TestStoreRejectsAnEmptyPath(t *testing.T) {
	_, err := NewStore(parser.Evidence{Enabled: true, Path: ""})
	assert.Error(t, err)
}

func TestDecodeHexEscapeRecoversTheOriginalBytes(t *testing.T) {
	original := []byte{0x00, 0x01, 0x5C, 0xFF, 0x41}

	encoded := hexEscape(original)
	assert.Equal(t, original, decodeHexEscape(encoded))
}

// hexEscape mirrors the escaping of the TCP strategy.
func hexEscape(raw []byte) string {
	var builder strings.Builder
	for _, b := range raw {
		if b >= 32 && b <= 126 && b != '\\' {
			builder.WriteByte(b)
			continue
		}
		builder.WriteString("\\x")
		const hexDigits = "0123456789abcdef"
		builder.WriteByte(hexDigits[b>>4])
		builder.WriteByte(hexDigits[b&0x0f])
	}
	return builder.String()
}

func mustRoot(t *testing.T, store *Store) string {
	t.Helper()
	return store.root
}

func listSamples(t *testing.T, root string) []Sample {
	t.Helper()

	var samples []Sample

	directories, err := os.ReadDir(root)
	require.NoError(t, err)

	for _, directory := range directories {
		if !directory.IsDir() {
			continue
		}
		files, err := os.ReadDir(filepath.Join(root, directory.Name()))
		require.NoError(t, err)
		for _, file := range files {
			if !strings.HasSuffix(file.Name(), ".json") {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(root, directory.Name(), file.Name()))
			require.NoError(t, err)
			var sample Sample
			require.NoError(t, json.Unmarshal(raw, &sample))
			samples = append(samples, sample)
		}
	}

	return samples
}

func readStoredSample(t *testing.T, root string) []byte {
	t.Helper()

	samples := listSamples(t, root)
	require.Len(t, samples, 1)

	raw, err := os.ReadFile(filepath.Join(root, samples[0].SHA256[:2], samples[0].SHA256+".bin"))
	require.NoError(t, err)

	return raw
}

func TestStoreTightensAnExistingDirectory(t *testing.T) {
	root := filepath.Join(t.TempDir(), "samples")
	require.NoError(t, os.MkdirAll(root, 0o755))

	_, err := NewStore(parser.Evidence{Enabled: true, Path: root})
	require.NoError(t, err)

	info, err := os.Stat(root)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm(),
		"an existing directory must be tightened: the samples are hostile content")
}
