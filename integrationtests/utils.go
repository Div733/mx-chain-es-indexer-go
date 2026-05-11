package integrationtests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"

	"github.com/elastic/go-elasticsearch/v7"
	"github.com/multiversx/mx-chain-core-go/core/pubkeyConverter"
	"github.com/multiversx/mx-chain-es-indexer-go/client"
	"github.com/multiversx/mx-chain-es-indexer-go/client/logging"
	"github.com/multiversx/mx-chain-es-indexer-go/config"
	"github.com/multiversx/mx-chain-es-indexer-go/mock"
	"github.com/multiversx/mx-chain-es-indexer-go/process/dataindexer"
	"github.com/multiversx/mx-chain-es-indexer-go/process/elasticproc"
	"github.com/multiversx/mx-chain-es-indexer-go/process/elasticproc/factory"
	logger "github.com/multiversx/mx-chain-logger-go"
)

var (
	// nolint
	log                = logger.GetOrCreate("integration-tests")
	pubKeyConverter, _ = pubkeyConverter.NewBech32PubkeyConverter(32, addressPrefix)
)

// nolint
func setLogLevelDebug() {
	_ = logger.SetLogLevel("process:DEBUG")
}

// nolint
func createESClient(url string) (elasticproc.DatabaseClientHandler, error) {
	return client.NewElasticClient(elasticsearch.Config{
		Addresses: []string{url},
		Logger:    &logging.CustomLogger{},
	})
}

// nolint
func decodeAddress(address string) []byte {
	decoded, err := pubKeyConverter.Decode(address)
	log.LogIfError(err, "address", address)

	return decoded
}

// CreateElasticProcessorWithIndexes -
func CreateElasticProcessorWithIndexes(
	esClient elasticproc.DatabaseClientHandler,
	enabledIndexes []string,
) (dataindexer.ElasticProcessor, error) {
	args := factory.ArgElasticProcessorFactory{
		Marshalizer:              &mock.MarshalizerMock{},
		Hasher:                   &mock.HasherMock{},
		AddressPubkeyConverter:   pubKeyConverter,
		ValidatorPubkeyConverter: mock.NewPubkeyConverterMock(32),
		DBClient:                 esClient,
		EnabledIndexes:           enabledIndexes,
		Denomination:             18,
		EnableEpochsConfig: config.EnableEpochsConfig{
			RelayedTransactionsV1V2DisableEpoch: 1,
		},
		NumWritesInParallel: 4,
	}

	return factory.CreateElasticProcessor(args)
}

// CreateElasticProcessor -
func CreateElasticProcessor(
	esClient elasticproc.DatabaseClientHandler,
) (dataindexer.ElasticProcessor, error) {
	args := factory.ArgElasticProcessorFactory{
		Marshalizer:              &mock.MarshalizerMock{},
		Hasher:                   &mock.HasherMock{},
		AddressPubkeyConverter:   pubKeyConverter,
		ValidatorPubkeyConverter: mock.NewPubkeyConverterMock(32),
		DBClient:                 esClient,
		EnabledIndexes: []string{dataindexer.TransactionsIndex, dataindexer.LogsIndex, dataindexer.AccountsESDTIndex, dataindexer.ScResultsIndex,
			dataindexer.ReceiptsIndex, dataindexer.BlockIndex, dataindexer.AccountsIndex, dataindexer.TokensIndex, dataindexer.TagsIndex, dataindexer.EventsIndex,
			dataindexer.OperationsIndex, dataindexer.DelegatorsIndex, dataindexer.ESDTsIndex, dataindexer.SCDeploysIndex, dataindexer.MiniblocksIndex, dataindexer.ValuesIndex, dataindexer.ExecutionResultsIndex},
		Denomination: 18,
		EnableEpochsConfig: config.EnableEpochsConfig{
			RelayedTransactionsV1V2DisableEpoch: 1,
		},
		NumWritesInParallel: 1,
	}

	return factory.CreateElasticProcessor(args)
}

// nolint
func readExpectedResult(path string) string {
	jsonFile, _ := os.Open(path)
	byteValue, _ := io.ReadAll(jsonFile)

	return string(byteValue)
}

// nolint
func getElementFromSlice(path string, index int) string {
	fileBytes := readExpectedResult(path)
	slice := make([]map[string]interface{}, 0)
	_ = json.Unmarshal([]byte(fileBytes), &slice)
	res, _ := json.Marshal(slice[index]["_source"])

	return string(res)
}

// nolint
func deleteDocumentByID(esClient elasticproc.DatabaseClientHandler, index string, id string) error {
	body := map[string]interface{}{
		"query": map[string]interface{}{
			"ids": map[string]interface{}{
				"values": []string{id},
			},
		},
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	return esClient.DoQueryRemove(context.Background(), index, bytes.NewBuffer(encoded))
}

// nolint
func getIndexMappings(index string) (string, error) {
	u, _ := url.Parse(esURL)
	u.Path = path.Join(u.Path, index, "_mappings")
	res, err := http.Get(u.String())
	if err != nil {
		return "", err
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	if res.StatusCode >= 400 {
		return "", fmt.Errorf("%s", string(body))
	}

	return string(body), nil
}
