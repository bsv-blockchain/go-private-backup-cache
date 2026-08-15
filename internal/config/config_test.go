package config_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-private-backup-cache/internal/config"
)

const validKey = "0000000000000000000000000000000000000000000000000000000000000001"

func TestLoadRequiresServerPrivateKey(t *testing.T) {
	// Every route is authenticated, so a server without an identity is useless and must
	// not start pretending otherwise.
	t.Setenv("SERVER_PRIVATE_KEY", "")
	_, err := config.Load()
	require.Error(t, err)
	require.Contains(t, err.Error(), "SERVER_PRIVATE_KEY")
}

func TestLoadRejectsMalformedKeys(t *testing.T) {
	for _, bad := range []string{"nothex", strings.Repeat("a", 63), strings.Repeat("z", 64)} {
		t.Setenv("SERVER_PRIVATE_KEY", bad)
		_, err := config.Load()
		require.Error(t, err, "key %q must be rejected", bad)
	}
}

func TestLoadDefaults(t *testing.T) {
	t.Setenv("SERVER_PRIVATE_KEY", validKey)
	cfg, err := config.Load()
	require.NoError(t, err)
	require.Equal(t, 8080, cfg.Port)
	require.Equal(t, config.DefaultMaxBlobBytes, cfg.MaxBlobBytes)
	require.Equal(t, "json", cfg.LogFormat)
}
