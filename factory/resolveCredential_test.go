package factory

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolveCredential_UsesConfigValueWhenEnvVarNameEmpty(t *testing.T) {
	t.Parallel()

	result := resolveCredential("config-password", "")
	require.Equal(t, "config-password", result)
}

func TestResolveCredential_UsesEnvVarWhenSet(t *testing.T) {
	envKey := "TEST_ES_PASSWORD_RESOLVE"
	require.Nil(t, os.Setenv(envKey, "env-password"))
	defer func() { _ = os.Unsetenv(envKey) }()

	result := resolveCredential("config-password", envKey)
	require.Equal(t, "env-password", result)
}

func TestResolveCredential_FallsBackToConfigWhenEnvVarEmpty(t *testing.T) {
	envKey := "TEST_ES_PASSWORD_EMPTY"
	require.Nil(t, os.Unsetenv(envKey))

	result := resolveCredential("config-password", envKey)
	require.Equal(t, "config-password", result)
}

func TestResolveCredential_EmptyConfigAndEmptyEnvReturnsEmpty(t *testing.T) {
	t.Parallel()

	result := resolveCredential("", "")
	require.Equal(t, "", result)
}
