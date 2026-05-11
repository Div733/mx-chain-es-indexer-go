package logsevents

import (
	"strings"
	"testing"

	"github.com/multiversx/mx-chain-es-indexer-go/data"
	"github.com/stretchr/testify/require"
)

func TestSerializeDRWADenials_UsesEventOrderInDocumentID(t *testing.T) {
	t.Parallel()

	buffSlice := data.NewBufferSlice(1024)
	lep := &logsAndEventsProcessor{}

	err := lep.SerializeDRWADenials([]*data.DrwaDenialRecord{
		{TxHash: "txHash", DenialCode: "CODE", EventOrder: 0},
		{TxHash: "txHash", DenialCode: "CODE", EventOrder: 1},
	}, buffSlice, "drwa-denials")
	require.NoError(t, err)

	payload := buffSlice.Buffers()[0].String()
	require.Contains(t, payload, `"txHash-denial-CODE-0"`)
	require.Contains(t, payload, `"txHash-denial-CODE-1"`)
}

func TestPrepareDRWARecord_RejectsOverlongDocumentID(t *testing.T) {
	t.Parallel()

	meta, serialized, err := prepareDRWARecord(strings.Repeat("a", maxDRWADocumentIDLength+1), "drwa-denials", &data.DrwaDenialRecord{})

	require.Error(t, err)
	require.Nil(t, meta)
	require.Nil(t, serialized)
}

func TestSerializeDRWAAttestations_UsesEventOrderInDocumentID(t *testing.T) {
	t.Parallel()

	buffSlice := data.NewBufferSlice(1024)
	lep := &logsAndEventsProcessor{}

	err := lep.SerializeDRWAAttestations([]*data.DrwaAttestationRecord{
		{TxHash: "txHash", EventType: "drwaAttestationRecorded", Auditor: "erd1auditor", EventOrder: 2},
		{TxHash: "txHash", EventType: "drwaAttestationRecorded", Auditor: "erd1auditor", EventOrder: 3},
	}, buffSlice, "drwa-attestations")
	require.NoError(t, err)

	payload := buffSlice.Buffers()[0].String()
	require.Contains(t, payload, `"txHash-drwaAttestationRecorded-erd1auditor-2"`)
	require.Contains(t, payload, `"txHash-drwaAttestationRecorded-erd1auditor-3"`)
}

func TestSerializeDRWAIdentities_UsesEventOrderInDocumentID(t *testing.T) {
	t.Parallel()

	buffSlice := data.NewBufferSlice(1024)
	lep := &logsAndEventsProcessor{}

	err := lep.SerializeDRWAIdentities([]*data.DrwaIdentityRecord{
		{TxHash: "txHash", Subject: "erd1subject", EventType: "drwaIdentityRegistered", EventOrder: 2},
		{TxHash: "txHash", Subject: "erd1subject", EventType: "drwaComplianceUpdated", EventOrder: 3},
	}, buffSlice, "drwa-identities")
	require.NoError(t, err)

	payload := buffSlice.Buffers()[0].String()
	require.Contains(t, payload, `"txHash-erd1subject-drwaIdentityRegistered-2"`)
	require.Contains(t, payload, `"txHash-erd1subject-drwaComplianceUpdated-3"`)
}
