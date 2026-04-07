package data

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDRWAEventMaterialization_JSONRoundTrip(t *testing.T) {
	t.Parallel()

	record := DRWAEventMaterialization{
		TxHash:        "tx-1",
		Identifier:    "drwaTransferDenied",
		TokenID:       "CARBON-123",
		Holder:        "erd1holder",
		PolicyVersion: 7,
		DenialCode:    "DRWA_JURISDICTION_BLOCKED",
		Topics:        []string{"topic-1", "topic-2"},
		Timestamp:     123,
		TimestampMs:   123456,
	}

	payload, err := json.Marshal(record)
	require.NoError(t, err)

	var decoded DRWAEventMaterialization
	require.NoError(t, json.Unmarshal(payload, &decoded))
	require.Equal(t, record, decoded)
}

func TestDrwaDenialRecord_JSONFieldNames(t *testing.T) {
	t.Parallel()

	record := DrwaDenialRecord{
		TxHash:      "tx-2",
		TokenID:     "HOTEL-001",
		Sender:      "erd1sender",
		Receiver:    "erd1receiver",
		DenialCode:  "DRWA_AML_BLOCKED",
		ShardID:     1,
		Timestamp:   999,
		TimestampMs: 999123,
	}

	payload, err := json.Marshal(record)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(payload, &decoded))
	require.Equal(t, "tx-2", decoded["txHash"])
	require.Equal(t, "HOTEL-001", decoded["tokenId"])
	require.Equal(t, "DRWA_AML_BLOCKED", decoded["denialCode"])
	require.EqualValues(t, 1, decoded["shardId"])
}

func TestDrwaHolderComplianceRecord_JSONRoundTrip(t *testing.T) {
	t.Parallel()

	record := DrwaHolderComplianceRecord{
		TxHash:              "tx-3",
		TokenID:             "HOTEL-001",
		Holder:              "erd1holder",
		HolderPolicyVersion: 4,
		KYCStatus:           "approved",
		AMLStatus:           "approved",
		InvestorClass:       "accredited",
		JurisdictionCode:    "SG",
		TransferLocked:      true,
		ReceiveLocked:       false,
		AuditorAuthorized:   true,
		ExpiryRound:         77,
		Timestamp:           456,
		TimestampMs:         456789,
	}

	payload, err := json.Marshal(record)
	require.NoError(t, err)

	var decoded DrwaHolderComplianceRecord
	require.NoError(t, json.Unmarshal(payload, &decoded))
	require.Equal(t, record, decoded)
}

func TestDrwaAttestationRecord_JSONRoundTrip(t *testing.T) {
	t.Parallel()

	record := DrwaAttestationRecord{
		TxHash:        "tx-4",
		TokenID:       "CARBON-001",
		Subject:       "erd1subject",
		Auditor:       "erd1auditor",
		EventType:     "drwaAuditorAccepted",
		Approved:      true,
		AttestedRound: 88,
		Timestamp:     567,
		TimestampMs:   567890,
	}

	payload, err := json.Marshal(record)
	require.NoError(t, err)

	var decoded DrwaAttestationRecord
	require.NoError(t, json.Unmarshal(payload, &decoded))
	require.Equal(t, record, decoded)
}

func TestDrwaTokenPolicyRecord_JSONRoundTrip(t *testing.T) {
	t.Parallel()

	record := DrwaTokenPolicyRecord{
		TxHash:             "tx-5",
		TokenID:            "CARBON-001",
		EventType:          "drwaTokenPolicyUpdated",
		PolicyID:           "policy-1",
		Regulated:          true,
		GlobalPause:        false,
		StrictAuditorMode:  true,
		TokenPolicyVersion: 9,
		Timestamp:          678,
		TimestampMs:        678901,
	}

	payload, err := json.Marshal(record)
	require.NoError(t, err)

	var decoded DrwaTokenPolicyRecord
	require.NoError(t, json.Unmarshal(payload, &decoded))
	require.Equal(t, record, decoded)
}
