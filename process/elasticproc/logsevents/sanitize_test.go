package logsevents

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSanitizeLogString_RemovesNewlines(t *testing.T) {
	t.Parallel()

	result := sanitizeLogString("hash\ninjected line")
	require.NotContains(t, result, "\n")
	require.Contains(t, result, "hash")
	require.Contains(t, result, "injected line")
}

func TestSanitizeLogString_RemovesCarriageReturnAndTab(t *testing.T) {
	t.Parallel()

	result := sanitizeLogString("hash\r\nwith\ttab")
	require.NotContains(t, result, "\r")
	require.NotContains(t, result, "\n")
	require.NotContains(t, result, "\t")
}

func TestSanitizeLogString_TruncatesLongString(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("a", 200)
	result := sanitizeLogString(long)
	require.LessOrEqual(t, len(result), 164) // 150 + len("...[truncated]")
	require.Contains(t, result, "...[truncated]")
}

func TestSanitizeLogString_ShortStringUnchanged(t *testing.T) {
	t.Parallel()

	require.Equal(t, "abc123def", sanitizeLogString("abc123def"))
}
