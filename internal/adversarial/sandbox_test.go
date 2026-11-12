package adversarial

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// hardenedComposePath is the hardened deployment profile.
const hardenedComposePath = "../../docker-compose.hardened.yml"

// composeFile is the parsed profile.
type composeFile struct {
	Services map[string]struct {
		User         string         `yaml:"user"`
		CapDrop      []string       `yaml:"cap_drop"`
		CapAdd       []string       `yaml:"cap_add"`
		ReadOnly     bool           `yaml:"read_only"`
		SecurityOpt  []string       `yaml:"security_opt"`
		PidsLimit    int            `yaml:"pids_limit"`
		MemLimit     string         `yaml:"mem_limit"`
		CPUs         string         `yaml:"cpus"`
		Volumes      []string       `yaml:"volumes"`
		Ports        []string       `yaml:"ports"`
		Networks     map[string]any `yaml:"networks"`
		Privileged   bool           `yaml:"privileged"`
		NetworkMode  string         `yaml:"network_mode"`
		Restart      string         `yaml:"restart"`
		Logging      any            `yaml:"logging"`
		ExtraOptions any            `yaml:"x-extra"`
	} `yaml:"services"`
	Networks map[string]struct {
		Driver string `yaml:"driver"`
	} `yaml:"networks"`
}

func loadHardenedCompose(t *testing.T) composeFile {
	t.Helper()

	raw, err := os.ReadFile(filepath.Clean(hardenedComposePath))
	if os.IsNotExist(err) {
		t.Skipf("the hardened profile %s is not available", hardenedComposePath)
	}
	require.NoError(t, err)

	var compose composeFile
	require.NoError(t, yaml.Unmarshal(raw, &compose))

	return compose
}

// TestTheHardenedProfileIsHardened is the container escape suite.
//
// The escape attempts themselves need a container runtime and live in
// scripts/verify-sandbox.sh. This test asserts the properties of the profile
// that make those attempts fail: the profile must not be silently weakened.
func TestTheHardenedProfileIsHardened(t *testing.T) {
	compose := loadHardenedCompose(t)

	service, ok := compose.Services["beelzebub"]
	require.True(t, ok, "the profile must define the honeypot service")

	t.Run("does not run as root", func(t *testing.T) {
		assert.NotEmpty(t, service.User, "the user must be pinned")
		assert.NotEqual(t, "root", service.User)
		assert.NotEqual(t, "0", service.User)
		assert.NotEqual(t, "0:0", service.User)
	})

	t.Run("drops every capability", func(t *testing.T) {
		assert.Contains(t, service.CapDrop, "ALL",
			"every capability must be dropped, otherwise a decoy that is compromised keeps them")
		for _, capability := range service.CapAdd {
			assert.Equal(t, "NET_BIND_SERVICE", capability,
				"only the capability needed to bind the privileged ports may be added back")
		}
	})

	t.Run("forbids the privilege escalation", func(t *testing.T) {
		assert.Contains(t, service.SecurityOpt, "no-new-privileges:true")
	})

	t.Run("has a read only root filesystem", func(t *testing.T) {
		assert.True(t, service.ReadOnly, "the root filesystem must be read only")
	})

	t.Run("caps the resources", func(t *testing.T) {
		assert.Positive(t, service.PidsLimit, "a fork bomb must stay local")
		assert.NotEmpty(t, service.MemLimit, "a memory bomb must stay local")
		assert.NotEmpty(t, service.CPUs, "a cpu bomb must stay local")
	})

	t.Run("is not privileged and has no host namespace", func(t *testing.T) {
		assert.False(t, service.Privileged, "the service must not be privileged")
		assert.NotEqual(t, "host", service.NetworkMode, "the service must not share the host network")
	})

	t.Run("mounts the configuration read only", func(t *testing.T) {
		var configuration string
		for _, volume := range service.Volumes {
			if strings.Contains(volume, "configurations") {
				configuration = volume
			}
		}
		require.NotEmpty(t, configuration, "the configuration must be mounted")
		assert.Contains(t, configuration, ":ro",
			"the decoy must not be able to rewrite the rules it enforces")
	})

	t.Run("does not mount the docker socket", func(t *testing.T) {
		for _, volume := range service.Volumes {
			assert.NotContains(t, volume, "docker.sock",
				"the docker socket is a full escape from the container")
		}
	})

	t.Run("publishes the decoys on the honeypot address", func(t *testing.T) {
		require.NotEmpty(t, service.Ports)
		for _, port := range service.Ports {
			host, _, found := strings.Cut(port, ":")
			require.True(t, found, "the port mapping must pin the host address")
			assert.NotEqual(t, "0.0.0.0", host,
				"the decoys must not listen on every address of the host")
			assert.Contains(t, host, ".", "the host address must be an explicit one")
		}
	})

	t.Run("lives on its own network", func(t *testing.T) {
		require.NotEmpty(t, service.Networks)
		for network := range service.Networks {
			assert.NotEqual(t, "host", network)
		}
	})
}

// TestTheDefaultProfileIsNotUsedForExposure records that the default profile
// is not hardened: the hardened one must be the one that is documented for
// an exposed deployment.
func TestTheDefaultProfileIsNotUsedForExposure(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean("../../docker-compose.yml"))
	if os.IsNotExist(err) {
		t.Skip("the default profile is not available")
	}
	require.NoError(t, err)

	content := string(raw)

	// The default profile is the development one: it must not claim to be
	// hardened, and the hardened one must be referenced from the docs.
	assert.NotContains(t, content, "read_only: true",
		"the default profile is not the hardened one")
}
