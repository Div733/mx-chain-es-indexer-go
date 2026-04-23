//go:build integrationtests

package integrationtests

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/multiversx/mx-chain-core-go/data/outport"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-es-indexer-go/mock"
	blockproc "github.com/multiversx/mx-chain-es-indexer-go/process/elasticproc/block"
	"github.com/multiversx/mx-chain-es-indexer-go/process/elasticproc"
	indexerdata "github.com/multiversx/mx-chain-es-indexer-go/process/dataindexer"
	dataBlock "github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/stretchr/testify/require"
)

func TestDRWAIdentityRecordFinalizedThenRemovedOnRevert(t *testing.T) {
	setLogLevelDebug()

	esClient, err := createESClient(esURL)
	require.NoError(t, err)

	esProc, err := CreateElasticProcessorWithIndexes(esClient, []string{
		indexerdata.TransactionsIndex,
		indexerdata.LogsIndex,
		indexerdata.EventsIndex,
		indexerdata.OperationsIndex,
		indexerdata.DrwaDenialsIndex,
		indexerdata.DrwaIdentitiesIndex,
		indexerdata.DrwaHolderComplianceIndex,
		indexerdata.DrwaAttestationsIndex,
		indexerdata.DrwaTokenPoliciesIndex,
		indexerdata.DrwaControlEventsIndex,
	})
	require.NoError(t, err)

	txHashBytes := []byte("drwa-identity-finality")
	txHashHex := hex.EncodeToString(txHashBytes)
	subject := "erd1subject"
	header := &dataBlock.Header{
		Round:     777,
		TimeStamp: 1700000000,
		ShardID:   2,
	}

	docID := txHashHex + "-" + subject + "-drwaIdentityRegistered-0"

	// Clean up any stale document from a previous run so the test is isolated.
	_ = deleteDocumentByID(esClient, indexerdata.DrwaIdentitiesIndex, docID)
	t.Cleanup(func() {
		_ = deleteDocumentByID(esClient, indexerdata.DrwaIdentitiesIndex, docID)
	})

	body := &dataBlock.Body{
		MiniBlocks: dataBlock.MiniBlockSlice{
			{
				TxHashes: [][]byte{txHashBytes},
				Type:     dataBlock.TxBlock,
			},
		},
	}

	blockProcessor, err := blockproc.NewBlockProcessor(&mock.HasherMock{}, &mock.MarshalizerMock{}, mock.NewPubkeyConverterMock(32))
	require.NoError(t, err)
	headerHash, err := blockProcessor.ComputeHeaderHash(header)
	require.NoError(t, err)

	pool := &outport.TransactionPool{
		Logs: []*outport.LogData{
			{
				TxHash: txHashHex,
				Log: &transaction.Log{
					Address: []byte("drwa-registry"),
					Events: []*transaction.Event{
						{
							Address:    []byte("drwa-registry"),
							Identifier: []byte("drwaIdentityRegistered"),
							Topics: [][]byte{
								[]byte(subject),
								[]byte("US"),
								[]byte("company"),
							},
						},
					},
				},
			},
		},
		Transactions: map[string]*outport.TxInfo{
			txHashHex: {
				Transaction:    &transaction.Transaction{},
				ExecutionOrder: 0,
			},
		},
	}

	outportBlock := createOutportBlockWithHeader(body, header, pool, nil, testNumOfShards)
	outportBlock.BlockData.HeaderHash = headerHash

	err = esProc.SaveTransactions(outportBlock)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		found, source := fetchIndexedDocument(t, esClient, indexerdata.DrwaIdentitiesIndex, docID)
		if !found {
			return false
		}

		return source["blockHash"] == hex.EncodeToString(headerHash) &&
			uint64(source["blockRound"].(float64)) == header.GetRound() &&
			source["isFinalized"] == nil
	}, 5*time.Second, 200*time.Millisecond)

	err = esProc.FinalizedBlock(&outport.FinalizedBlock{
		ShardID:    header.GetShardID(),
		HeaderHash: headerHash,
	})
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		found, source := fetchIndexedDocument(t, esClient, indexerdata.DrwaIdentitiesIndex, docID)
		if !found {
			return false
		}

		value, ok := source["isFinalized"].(bool)
		return ok && value
	}, 5*time.Second, 200*time.Millisecond)

	err = esProc.RemoveTransactions(header, body, header.GetTimeStamp()*1000)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		found, _ := fetchIndexedDocument(t, esClient, indexerdata.DrwaIdentitiesIndex, docID)
		return !found
	}, 5*time.Second, 200*time.Millisecond)
}

func fetchIndexedDocument(
	t *testing.T,
	esClient elasticproc.DatabaseClientHandler,
	index string,
	id string,
) (bool, map[string]interface{}) {
	t.Helper()

	response := &GenericResponse{}
	err := esClient.DoMultiGet(context.Background(), []string{id}, index, true, response)
	require.NoError(t, err)
	require.Len(t, response.Docs, 1)

	if !response.Docs[0].Found {
		return false, nil
	}

	source := make(map[string]interface{})
	err = json.Unmarshal(response.Docs[0].Source, &source)
	require.NoError(t, err)

	return true, source
}
