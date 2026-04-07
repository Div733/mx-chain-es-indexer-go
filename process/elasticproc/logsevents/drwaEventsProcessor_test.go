package logsevents

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-es-indexer-go/data"
	"github.com/stretchr/testify/require"
)

func TestDRWAEventsProcessorMarksTransaction(t *testing.T) {
	t.Parallel()

	tx := &data.Transaction{}
	hash := "hash"
	proc := newDRWAEventsProcessor()

	res := proc.processEvent(&argsProcessEvent{
		event: &transaction.Event{Identifier: []byte(drwaTransferDeniedEvent)},
		txs: map[string]*data.Transaction{
			hash: tx,
		},
		txHashHexEncoded: hash,
	})

	require.True(t, res.processed)
	require.True(t, tx.HasOperations)
	require.Equal(t, "drwa", tx.Operation)
	require.Equal(t, drwaTransferDeniedEvent, tx.Function)
}

func TestDRWAEventsProcessorBuildsTokenInfoForAssetRegistration(t *testing.T) {
	t.Parallel()

	proc := newDRWAEventsProcessor()
	res := proc.processEvent(&argsProcessEvent{
		event: &transaction.Event{
			Identifier: []byte(drwaAssetRegisteredEvent),
			Topics: [][]byte{
				[]byte("HOTEL-1234"),
				[]byte("policy-hotel-1"),
				[]byte("true"),
			},
		},
		txs:              map[string]*data.Transaction{},
		txHashHexEncoded: "hash",
	})

	require.True(t, res.processed)
	require.NotNil(t, res.tokenInfo)
	require.Equal(t, "HOTEL-1234", res.tokenInfo.Token)
	require.True(t, res.tokenInfo.Drwa.Regulated)
	require.Equal(t, "policy-hotel-1", res.tokenInfo.Drwa.PolicyID)
}

func TestDRWAEventsProcessorBuildsTokenInfoForTokenPolicy(t *testing.T) {
	t.Parallel()

	proc := newDRWAEventsProcessor()
	res := proc.processEvent(&argsProcessEvent{
		event: &transaction.Event{
			Identifier: []byte(drwaTokenPolicyEvent),
			Topics: [][]byte{
				[]byte("HOTEL-1234"),
				[]byte("true"),
				[]byte("true"),
				[]byte("false"),
				{2},
			},
		},
		txs:              map[string]*data.Transaction{},
		txHashHexEncoded: "hash",
	})

	require.True(t, res.processed)
	require.NotNil(t, res.tokenInfo)
	require.True(t, res.tokenInfo.Drwa.Regulated)
	require.True(t, res.tokenInfo.Drwa.GlobalPause)
	require.False(t, res.tokenInfo.Drwa.StrictAuditorMode)
	require.Equal(t, uint64(2), res.tokenInfo.Drwa.TokenPolicyVersion)
	require.NotNil(t, res.drwaTokenPolicy)
	require.Equal(t, "HOTEL-1234", res.drwaTokenPolicy.TokenID)
	require.Equal(t, uint64(2), res.drwaTokenPolicy.TokenPolicyVersion)
}

func TestDRWAEventsProcessorBuildsHolderComplianceRecord(t *testing.T) {
	t.Parallel()

	proc := newDRWAEventsProcessor()
	res := proc.processEvent(&argsProcessEvent{
		event: &transaction.Event{
			Identifier: []byte(drwaHolderComplianceEvent),
			Topics: [][]byte{
				[]byte("HOTEL-1234"),
				[]byte("erd1holder"),
				{3},
				[]byte("approved"),
				[]byte("approved"),
				[]byte("QIB"),
				[]byte("US"),
				{9},
				[]byte("true"),
				[]byte("false"),
				[]byte("true"),
			},
		},
		txs:              map[string]*data.Transaction{},
		txHashHexEncoded: "hash",
	})

	require.True(t, res.processed)
	require.NotNil(t, res.drwaHolderCompliance)
	require.Equal(t, "HOTEL-1234", res.drwaHolderCompliance.TokenID)
	require.Equal(t, "erd1holder", res.drwaHolderCompliance.Holder)
	require.Equal(t, uint64(3), res.drwaHolderCompliance.HolderPolicyVersion)
	require.Equal(t, "approved", res.drwaHolderCompliance.KYCStatus)
	require.Equal(t, "approved", res.drwaHolderCompliance.AMLStatus)
	require.Equal(t, "QIB", res.drwaHolderCompliance.InvestorClass)
	require.Equal(t, "US", res.drwaHolderCompliance.JurisdictionCode)
	require.Equal(t, uint64(9), res.drwaHolderCompliance.ExpiryRound)
	require.True(t, res.drwaHolderCompliance.TransferLocked)
	require.False(t, res.drwaHolderCompliance.ReceiveLocked)
	require.True(t, res.drwaHolderCompliance.AuditorAuthorized)
}

func TestDRWAEventsProcessorBuildsAttestationRecord(t *testing.T) {
	t.Parallel()

	proc := newDRWAEventsProcessor()
	res := proc.processEvent(&argsProcessEvent{
		event: &transaction.Event{
			Identifier: []byte(drwaAttestationRecordedEvent),
			Topics: [][]byte{
				[]byte("HOTEL-1234"),
				[]byte("erd1subject"),
				[]byte("erd1auditor"),
				[]byte("kyc"),
				[]byte("true"),
				{7},
			},
		},
		txs:              map[string]*data.Transaction{},
		txHashHexEncoded: "hash",
	})

	require.True(t, res.processed)
	require.NotNil(t, res.drwaAttestation)
	require.Equal(t, "HOTEL-1234", res.drwaAttestation.TokenID)
	require.Equal(t, "erd1subject", res.drwaAttestation.Subject)
	require.Equal(t, "erd1auditor", res.drwaAttestation.Auditor)
	require.Equal(t, drwaAttestationRecordedEvent, res.drwaAttestation.EventType)
	require.True(t, res.drwaAttestation.Approved)
	require.Equal(t, uint64(7), res.drwaAttestation.AttestedRound)
}
