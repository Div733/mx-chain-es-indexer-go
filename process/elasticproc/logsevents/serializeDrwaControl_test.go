package logsevents

import (
	"testing"

	"github.com/multiversx/mx-chain-es-indexer-go/data"
	"github.com/stretchr/testify/require"
)

func TestSerializeDRWAControlEvents_UsesEventOrderInDocumentID(t *testing.T) {
	t.Parallel()

	buffSlice := data.NewBufferSlice(1024)
	lep := &logsAndEventsProcessor{}

	err := lep.SerializeDRWAControlEvents([]*data.DrwaControlEventRecord{
		{TxHash: "txHash", EventType: "drwaGovernanceProposed", EventOrder: 0},
		{TxHash: "txHash", EventType: "drwaGovernanceProposed", EventOrder: 1},
	}, buffSlice, "drwa-control-events")
	require.NoError(t, err)

	payload := buffSlice.Buffers()[0].String()
	require.Contains(t, payload, `"txHash-drwaGovernanceProposed-0"`)
	require.Contains(t, payload, `"txHash-drwaGovernanceProposed-1"`)
}
