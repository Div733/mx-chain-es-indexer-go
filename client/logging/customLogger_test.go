package logging

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSanitizeLogMessage_RemovesNewlines(t *testing.T) {
	t.Parallel()

	input := "error: connection refused\nfake log entry"
	result := sanitizeLogMessage(input)
	require.NotContains(t, result, "\n")
	require.Contains(t, result, "error: connection refused")
	require.Contains(t, result, "fake log entry")
}

func TestSanitizeLogMessage_RemovesCarriageReturn(t *testing.T) {
	t.Parallel()

	input := "error\r\ninjected"
	result := sanitizeLogMessage(input)
	require.NotContains(t, result, "\r")
	require.NotContains(t, result, "\n")
}

func TestSanitizeLogMessage_RemovesTabs(t *testing.T) {
	t.Parallel()

	result := sanitizeLogMessage("error\tinjected")
	require.NotContains(t, result, "\t")
}

func TestSanitizeLogMessage_TruncatesLongMessage(t *testing.T) {
	t.Parallel()

	long := make([]byte, 600)
	for i := range long {
		long[i] = 'a'
	}
	result := sanitizeLogMessage(string(long))
	require.LessOrEqual(t, len(result), 514) // 500 + len("...[truncated]")
	require.Contains(t, result, "...[truncated]")
}

func TestSanitizeLogMessage_ShortMessageUnchanged(t *testing.T) {
	t.Parallel()

	input := "simple error"
	require.Equal(t, input, sanitizeLogMessage(input))
}
