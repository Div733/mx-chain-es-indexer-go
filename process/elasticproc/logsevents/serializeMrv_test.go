package logsevents

import (
	"strings"
	"testing"

	"github.com/multiversx/mx-chain-es-indexer-go/data"
	"github.com/stretchr/testify/require"
)

func TestSerializeMRVAnchoredProofs_UsesReportAndEventOrderInDocumentID(t *testing.T) {
	t.Parallel()

	lep := &logsAndEventsProcessor{}
	buffSlice := data.NewBufferSlice(1024)

	err := lep.SerializeMRVAnchoredProofs([]*data.MrvAnchoredProofRecord{
		{
			TxHash:     "hash",
			ReportID:   "report-1",
			EventType:  mrvReportAnchoredV2Event,
			EventOrder: 3,
		},
	}, buffSlice, "mrv-anchored-proofs")

	require.NoError(t, err)
	require.Len(t, buffSlice.Buffers(), 1)
	require.Contains(t, buffSlice.Buffers()[0].String(), `"mrv-anchored-proofs"`)
	require.Contains(t, buffSlice.Buffers()[0].String(), `"hash-report-1-mrvReportAnchoredV2-3"`)
}

func TestSerializeMRVAnchoredProofs_UsesMRVErrorLabel(t *testing.T) {
	t.Parallel()

	lep := &logsAndEventsProcessor{}
	buffSlice := data.NewBufferSlice(1024)

	err := lep.SerializeMRVAnchoredProofs([]*data.MrvAnchoredProofRecord{
		{
			TxHash:     strings.Repeat("a", maxDRWADocumentIDLength+1),
			ReportID:   "report-1",
			EventType:  mrvReportAnchoredV2Event,
			EventOrder: 3,
		},
	}, buffSlice, "mrv-anchored-proofs")

	require.EqualError(t, err, "MRV document id exceeds maximum length")
}
