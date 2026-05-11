package gin

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsAllowedCORSOrigin(t *testing.T) {
	t.Parallel()

	require.True(t, isAllowedCORSOrigin("http://localhost:8080"))
	require.True(t, isAllowedCORSOrigin("http://127.0.0.1:8080"))
	require.True(t, isAllowedCORSOrigin("http://[::1]:8080"))
	require.False(t, isAllowedCORSOrigin("http://evil.example"))
	require.False(t, isAllowedCORSOrigin("http://[::1"))
}
