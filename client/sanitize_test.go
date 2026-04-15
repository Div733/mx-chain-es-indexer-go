package client

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSanitizeElasticsearchError_NilError(t *testing.T) {
	t.Parallel()

	require.Equal(t, "", sanitizeElasticsearchError(nil))
}

func TestSanitizeElasticsearchError_RedactsIPAddress(t *testing.T) {
	t.Parallel()

	err := errors.New("connection refused at 10.0.1.50:9200")
	result := sanitizeElasticsearchError(err)
	require.NotContains(t, result, "10.0.1.50")
	require.Contains(t, result, "[IP_REDACTED]")
	require.Contains(t, result, "connection refused")
}

func TestSanitizeElasticsearchError_RedactsElasticsearchVersion(t *testing.T) {
	t.Parallel()

	err := errors.New("Elasticsearch 7.10.2 cluster error")
	result := sanitizeElasticsearchError(err)
	require.NotContains(t, result, "7.10.2")
	require.Contains(t, result, "[VERSION_REDACTED]")
}

func TestSanitizeElasticsearchError_RedactsNodeName(t *testing.T) {
	t.Parallel()

	err := errors.New("failed on [node-1] shard unavailable")
	result := sanitizeElasticsearchError(err)
	require.NotContains(t, result, "node-1")
	require.Contains(t, result, "[NODE_REDACTED]")
	require.Contains(t, result, "shard unavailable")
}

func TestSanitizeElasticsearchError_PreservesErrorType(t *testing.T) {
	t.Parallel()

	err := errors.New("index_not_found_exception: no such index")
	result := sanitizeElasticsearchError(err)
	require.Contains(t, result, "index_not_found_exception")
	require.Contains(t, result, "no such index")
}

func TestSanitizeElasticsearchError_RedactsMultipleSensitiveFields(t *testing.T) {
	t.Parallel()

	err := errors.New("Elasticsearch 7.10.2 [node-3] connection refused at 192.168.1.100:9200")
	result := sanitizeElasticsearchError(err)
	require.NotContains(t, result, "7.10.2")
	require.NotContains(t, result, "node-3")
	require.NotContains(t, result, "192.168.1.100")
	require.Contains(t, result, "[VERSION_REDACTED]")
	require.Contains(t, result, "[NODE_REDACTED]")
	require.Contains(t, result, "[IP_REDACTED]")
}
