//go:build integrationtests

package integrationtests

import (
	"context"
	"encoding/hex"
	"fmt"
	"testing"

	dataBlock "github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/outport"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-es-indexer-go/mock"
	indexerdata "github.com/multiversx/mx-chain-es-indexer-go/process/dataindexer"
	blockproc "github.com/multiversx/mx-chain-es-indexer-go/process/elasticproc/block"
	"github.com/stretchr/testify/require"
)

func TestDRWADebug(t *testing.T) {
	esClient, err := createESClient(esURL)
	require.NoError(t, err)

	esProc, err := CreateElasticProcessorWithIndexes(esClient, []string{
		indexerdata.TransactionsIndex,
		indexerdata.LogsIndex,
		indexerdata.EventsIndex,
		indexerdata.OperationsIndex,
		indexerdata.DrwaIdentitiesIndex,
	})
	require.NoError(t, err)

	txHashBytes := []byte("drwa-identity-finality")
	txHashHex := hex.EncodeToString(txHashBytes)
	subject := "erd1subject"
	header := &dataBlock.Header{Round: 777, TimeStamp: 1700000000, ShardID: 2}
	body := &dataBlock.Body{MiniBlocks: dataBlock.MiniBlockSlice{{TxHashes: [][]byte{txHashBytes}, Type: dataBlock.TxBlock}}}

	blockProcessor, _ := blockproc.NewBlockProcessor(&mock.HasherMock{}, &mock.MarshalizerMock{}, mock.NewPubkeyConverterMock(32))
	headerHash, _ := blockProcessor.ComputeHeaderHash(header)

	emitterBytes := decodeAddress(drwaTestEmitter)
	fmt.Printf("emitter bytes len=%d hex=%s\n", len(emitterBytes), hex.EncodeToString(emitterBytes))

	pool := &outport.TransactionPool{
		Logs: []*transaction.LogData{{
			TxHash: txHashHex,
			Log: &transaction.Log{
				Address: emitterBytes,
				Events: []*transaction.Event{{
					Address:    emitterBytes,
					Identifier: []byte("drwaIdentityRegistered"),
					Topics:     [][]byte{[]byte(subject), []byte("US"), []byte("company")},
				}},
			},
		}},
		Transactions: map[string]*outport.TxInfo{
			txHashHex: {Transaction: &transaction.Transaction{SndAddr: emitterBytes, RcvAddr: emitterBytes}, ExecutionOrder: 0},
		},
	}

	outportBlock := createOutportBlockWithHeader(body, header, pool, nil, testNumOfShards)
	outportBlock.BlockData.HeaderHash = headerHash

	err = esProc.SaveTransactions(outportBlock)
	require.NoError(t, err)

	docID := txHashHex + "-" + subject + "-drwaIdentityRegistered-0"
	fmt.Printf("looking for docID: %s in index: %s\n", docID, indexerdata.DrwaIdentitiesIndex)

	response := &GenericResponse{}
	err = esClient.DoMultiGet(context.Background(), []string{docID}, indexerdata.DrwaIdentitiesIndex, true, response)
	require.NoError(t, err)
	fmt.Printf("response docs count: %d\n", len(response.Docs))
	if len(response.Docs) > 0 {
		fmt.Printf("found=%v source=%s\n", response.Docs[0].Found, string(response.Docs[0].Source))
	}
}
