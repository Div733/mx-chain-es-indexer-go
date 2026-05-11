package main

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadConfigFile_EnablesAllDRWAIndices(t *testing.T) {
	t.Parallel()

	cfg, err := loadConfigFile(filepath.Join(".", "config"))
	require.NoError(t, err)

	enabled := make(map[string]struct{}, len(cfg.ClusterConfig.EnabledIndices))
	for _, index := range cfg.ClusterConfig.EnabledIndices {
		enabled[index] = struct{}{}
	}

	for _, expected := range []string{
		"drwa-denials",
		"drwa-holder-compliance",
		"drwa-attestations",
		"drwa-token-policies",
		"drwa-control-events",
		"drwa-identities",
		"mrv-anchored-proofs",
	} {
		_, ok := enabled[expected]
		require.Truef(t, ok, "expected index %q to be enabled in cluster.toml", expected)
	}
}
