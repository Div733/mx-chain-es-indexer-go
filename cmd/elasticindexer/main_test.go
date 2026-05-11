package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadClusterConfig_RequiresElasticCredentialsByDefault(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "prefs.toml")
	require.NoError(t, os.WriteFile(configPath, []byte(`
[config]
    [config.elastic-cluster]
        url = "http://localhost:9200"
        username = ""
        password = ""
        allow-insecure-no-auth-dev = false
`), 0600))

	_, err := loadClusterConfig(configPath)

	require.Error(t, err)
	require.Contains(t, err.Error(), "elasticsearch username and password are required")
}

func TestLoadClusterConfig_AllowsExplicitDevNoAuthOverride(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "prefs.toml")
	require.NoError(t, os.WriteFile(configPath, []byte(`
[config]
    [config.elastic-cluster]
        url = "http://localhost:9200"
        username = ""
        password = ""
        allow-insecure-no-auth-dev = true
`), 0600))

	_, err := loadClusterConfig(configPath)

	require.NoError(t, err)
}
