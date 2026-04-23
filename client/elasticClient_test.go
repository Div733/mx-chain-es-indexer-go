package client

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/elastic/go-elasticsearch/v7"
	"github.com/multiversx/mx-chain-es-indexer-go/client/logging"
	"github.com/multiversx/mx-chain-es-indexer-go/data"
	indexer "github.com/multiversx/mx-chain-es-indexer-go/process/dataindexer"
	"github.com/stretchr/testify/require"
)

func TestElasticClient_NewClientEmptyUrl(t *testing.T) {
	esClient, err := NewElasticClient(elasticsearch.Config{
		Addresses: []string{},
	})
	require.Nil(t, esClient)
	require.Equal(t, indexer.ErrNoElasticUrlProvided, err)
}

func TestElasticClient_NewClient(t *testing.T) {
	handler := http.NotFound
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler(w, r)
	}))
	defer ts.Close()

	handler = func(w http.ResponseWriter, r *http.Request) {
		resp := ``
		_, _ = w.Write([]byte(resp))
	}

	esClient, err := NewElasticClient(elasticsearch.Config{
		Addresses: []string{ts.URL},
	})
	require.Nil(t, err)
	require.NotNil(t, esClient)
}

func TestElasticClient_DoMultiGet(t *testing.T) {
	handler := http.NotFound
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler(w, r)
	}))
	defer ts.Close()

	handler = func(w http.ResponseWriter, r *http.Request) {
		jsonFile, err := os.Open("./testsData/response-multi-get.json")
		require.Nil(t, err)

		byteValue, _ := io.ReadAll(jsonFile)
		_, _ = w.Write(byteValue)
	}

	esClient, _ := NewElasticClient(elasticsearch.Config{
		Addresses: []string{ts.URL},
		Logger:    &logging.CustomLogger{},
	})

	ids := []string{"id"}
	res := &data.ResponseTokens{}
	err := esClient.DoMultiGet(context.Background(), ids, "tokens", true, res)
	require.Nil(t, err)
	require.Len(t, res.Docs, 3)

	resMap := make(objectsMap)
	err = esClient.DoMultiGet(context.Background(), ids, "tokens", true, &resMap)
	require.Nil(t, err)

	_, ok := resMap["docs"]
	require.True(t, ok)
}

func TestElasticClient_GetWriteIndexMultipleIndicesBehind(t *testing.T) {
	handler := http.NotFound
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler(w, r)
	}))
	defer ts.Close()

	handler = func(w http.ResponseWriter, r *http.Request) {
		jsonFile, err := os.Open("./testsData/response-get-alias.json")
		require.Nil(t, err)

		byteValue, _ := io.ReadAll(jsonFile)
		_, _ = w.Write(byteValue)
	}

	esClient, _ := NewElasticClient(elasticsearch.Config{
		Addresses: []string{ts.URL},
		Logger:    &logging.CustomLogger{},
	})
	res, err := esClient.getWriteIndex("blocks")
	require.Nil(t, err)
	require.Equal(t, "blocks-000004", res)
}

func TestElasticClient_GetWriteIndexOneIndex(t *testing.T) {
	handler := http.NotFound
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler(w, r)
	}))
	defer ts.Close()

	handler = func(w http.ResponseWriter, r *http.Request) {
		jsonFile, err := os.Open("./testsData/response-get-alias-only-one-index.json")
		require.Nil(t, err)

		byteValue, _ := io.ReadAll(jsonFile)
		_, _ = w.Write(byteValue)
	}

	esClient, _ := NewElasticClient(elasticsearch.Config{
		Addresses: []string{ts.URL},
		Logger:    &logging.CustomLogger{},
	})
	res, err := esClient.getWriteIndex("delegators")
	require.Nil(t, err)
	require.Equal(t, "delegators-000001", res)
}

func TestElasticClient_PutMappingsSanitizesElasticErrors(t *testing.T) {
	handler := http.NotFound
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler(w, r)
	}))
	defer ts.Close()

	handler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"type":"mapper_parsing_exception","reason":"token=super-secret-value-1234567890"}}`))
	}

	esClient, _ := NewElasticClient(elasticsearch.Config{
		Addresses: []string{ts.URL},
		Logger:    &logging.CustomLogger{},
	})

	err := esClient.PutMappings("tokens", bytes.NewBufferString(`{"properties":{}}`))
	require.Error(t, err)
	require.Contains(t, err.Error(), "mapper_parsing_exception")
	require.NotContains(t, err.Error(), "super-secret-value-1234567890")
}
