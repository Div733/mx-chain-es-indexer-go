package logsevents

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-es-indexer-go/data"
)

func BenchmarkDRWAEventsProcessor_ProcessPolicyEvent(b *testing.B) {
	processor := newTestDRWAEventsProcessorAllowAll()
	event := &transaction.Event{
		Identifier: []byte(drwaTokenPolicyEvent),
		Topics: [][]byte{
			[]byte("CARBON-123"),
			[]byte("true"),
			[]byte("false"),
			[]byte("true"),
			{5},
		},
	}
	args := &argsProcessEvent{
		event:            event,
		txHashHexEncoded: "txHash",
		txs:              map[string]*data.Transaction{"txHash": {}},
		scrs:             map[string]*data.ScResult{},
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = processor.processEvent(args)
	}
}
