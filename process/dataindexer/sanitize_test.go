package dataindexer

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSanitizeError_NilReturnsNil(t *testing.T) {
	t.Parallel()

	require.Nil(t, sanitizeError(nil))
}

func TestSanitizeError_RemovesNewlines(t *testing.T) {
	t.Parallel()

	err := errors.New("mapping conflict\nfake success line")
	result := sanitizeError(err)
	require.NotNil(t, result)
	require.NotContains(t, result.Error(), "\n")
	require.Contains(t, result.Error(), "mapping conflict")
	require.Contains(t, result.Error(), "fake success line")
}

func TestSanitizeError_RemovesCarriageReturnAndTab(t *testing.T) {
	t.Parallel()

	err := errors.New("error\r\nwith\ttabs")
	result := sanitizeError(err)
	require.NotContains(t, result.Error(), "\r")
	require.NotContains(t, result.Error(), "\n")
	require.NotContains(t, result.Error(), "\t")
}

func TestSanitizeError_TruncatesLongMessage(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("x", 400)
	result := sanitizeError(errors.New(long))
	require.NotNil(t, result)
	require.LessOrEqual(t, len(result.Error()), 314) // 300 + len("...[truncated]")
	require.Contains(t, result.Error(), "...[truncated]")
}

func TestSanitizeLogValue_RemovesNewlines(t *testing.T) {
	t.Parallel()

	result := sanitizeLogValue("abc\ndef")
	require.NotContains(t, result, "\n")
	require.Contains(t, result, "abc")
	require.Contains(t, result, "def")
}

func TestSanitizeLogValue_RemovesCarriageReturnAndTab(t *testing.T) {
	t.Parallel()

	result := sanitizeLogValue("val\r\nue\there")
	require.NotContains(t, result, "\r")
	require.NotContains(t, result, "\n")
	require.NotContains(t, result, "\t")
}

func TestSanitizeLogValue_TruncatesLongValue(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("a", 250)
	result := sanitizeLogValue(long)
	require.LessOrEqual(t, len(result), 214) // 200 + len("...[truncated]")
	require.Contains(t, result, "...[truncated]")
}

func TestSanitizeLogValue_ShortValueUnchanged(t *testing.T) {
	t.Parallel()

	require.Equal(t, "abc123", sanitizeLogValue("abc123"))
}
