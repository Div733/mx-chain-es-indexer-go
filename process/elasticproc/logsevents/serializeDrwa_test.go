package logsevents

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/multiversx/mx-chain-es-indexer-go/data"
	"github.com/stretchr/testify/require"
)

func newTestLogsProcessor() *logsAndEventsProcessor {
	return &logsAndEventsProcessor{}
}

func TestSerializeDRWADenials_WritesRecordToBuffer(t *testing.T) {
	t.Parallel()

	proc := newTestLogsProcessor()
	buff := data.NewBufferSlice(0)
	records := []*data.DrwaDenialRecord{
		{TxHash: "txhash1", TokenID: "HOTEL-1234", DenialCode: "2", ShardID: 0},
	}

	err := proc.SerializeDRWADenials(records, buff, "drwa-denials")
	require.Nil(t, err)
	require.Equal(t, 1, len(buff.Buffers()))

	content := buff.Buffers()[0].String()
	require.Contains(t, content, "txhash1")
	require.Contains(t, content, "HOTEL-1234")
	require.Contains(t, content, "drwa-denials")
}

func TestSerializeDRWADenials_UniqueIDsForSameCodeInOneTx(t *testing.T) {
	t.Parallel()

	proc := newTestLogsProcessor()
	buff := data.NewBufferSlice(0)
	records := []*data.DrwaDenialRecord{
		{TxHash: "txhash1", TokenID: "HOTEL-1234", DenialCode: "2"},
		{TxHash: "txhash1", TokenID: "HOTEL-1234", DenialCode: "2"},
	}

	err := proc.SerializeDRWADenials(records, buff, "drwa-denials")
	require.Nil(t, err)

	content := buff.Buffers()[0].String()
	require.Contains(t, content, "txhash1-denial-2-0")
	require.Contains(t, content, "txhash1-denial-2-1")
}

func TestSerializeDRWADenials_EmptyRecordsNoError(t *testing.T) {
	t.Parallel()

	proc := newTestLogsProcessor()
	buff := data.NewBufferSlice(0)
	err := proc.SerializeDRWADenials([]*data.DrwaDenialRecord{}, buff, "drwa-denials")
	require.Nil(t, err)
}

func TestSerializeDRWAHolderCompliance_WritesRecordToBuffer(t *testing.T) {
	t.Parallel()

	proc := newTestLogsProcessor()
	buff := data.NewBufferSlice(0)
	records := []*data.DrwaHolderComplianceRecord{
		{TxHash: "txhash1", TokenID: "HOTEL-1234", Holder: "erd1holder", KYCStatus: "approved"},
	}

	err := proc.SerializeDRWAHolderCompliance(records, buff, "drwa-holder-compliance")
	require.Nil(t, err)

	content := buff.Buffers()[0].String()
	require.Contains(t, content, "txhash1")
	require.Contains(t, content, "erd1holder")
	require.Contains(t, content, "drwa-holder-compliance")

	// verify JSON contains the field
	lines := strings.Split(strings.TrimSpace(content), "\n")
	require.Equal(t, 2, len(lines))
	var rec data.DrwaHolderComplianceRecord
	require.Nil(t, json.Unmarshal([]byte(lines[1]), &rec))
	require.Equal(t, "approved", rec.KYCStatus)
}

func TestSerializeDRWAAttestations_WritesRecordToBuffer(t *testing.T) {
	t.Parallel()

	proc := newTestLogsProcessor()
	buff := data.NewBufferSlice(0)
	records := []*data.DrwaAttestationRecord{
		{TxHash: "txhash1", Auditor: "erd1auditor", EventType: drwaAttestationRecordedEvent, AttestationType: "kyc"},
	}

	err := proc.SerializeDRWAAttestations(records, buff, "drwa-attestations")
	require.Nil(t, err)

	content := buff.Buffers()[0].String()
	require.Contains(t, content, "txhash1")
	require.Contains(t, content, "erd1auditor")
	require.Contains(t, content, "drwa-attestations")

	lines := strings.Split(strings.TrimSpace(content), "\n")
	require.Equal(t, 2, len(lines))
	var rec data.DrwaAttestationRecord
	require.Nil(t, json.Unmarshal([]byte(lines[1]), &rec))
	require.Equal(t, "kyc", rec.AttestationType)
}

func TestSerializeDRWATokenPolicies_WritesRecordToBuffer(t *testing.T) {
	t.Parallel()

	proc := newTestLogsProcessor()
	buff := data.NewBufferSlice(0)
	records := []*data.DrwaTokenPolicyRecord{
		{TxHash: "txhash1", TokenID: "HOTEL-1234", EventType: drwaTokenPolicyEvent, Regulated: true},
	}

	err := proc.SerializeDRWATokenPolicies(records, buff, "drwa-token-policies")
	require.Nil(t, err)

	content := buff.Buffers()[0].String()
	require.Contains(t, content, "txhash1")
	require.Contains(t, content, "HOTEL-1234")
	require.Contains(t, content, "drwa-token-policies")

	lines := strings.Split(strings.TrimSpace(content), "\n")
	require.Equal(t, 2, len(lines))
	var rec data.DrwaTokenPolicyRecord
	require.Nil(t, json.Unmarshal([]byte(lines[1]), &rec))
	require.True(t, rec.Regulated)
}
