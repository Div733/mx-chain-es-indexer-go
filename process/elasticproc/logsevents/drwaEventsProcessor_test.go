package logsevents

import (
	"testing"

	coredrwa "github.com/multiversx/mx-chain-core-go/data/drwa"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-es-indexer-go/data"
	"github.com/stretchr/testify/require"
)

func newTestDRWAEventsProcessorAllowAll() *drwaEventsProcessor {
	return &drwaEventsProcessor{
		authorizedEmitters: map[string]struct{}{"": struct{}{}},
	}
}

func TestDRWAEventsProcessorDefaultConstructorFailsClosed(t *testing.T) {
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
		logAddress:       []byte("any-emitter"),
		txs:              map[string]*data.Transaction{},
		txHashHexEncoded: "hash",
	})

	require.False(t, res.processed)
	require.Nil(t, res.tokenInfo)
}

func TestDRWAEventsProcessorMarksTransaction(t *testing.T) {
	t.Parallel()

	tx := &data.Transaction{}
	hash := "hash"
	proc := newTestDRWAEventsProcessorAllowAll()

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

	proc := newTestDRWAEventsProcessorAllowAll()
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

func TestDRWAEventsProcessorRejectsUnauthorizedEmitter(t *testing.T) {
	t.Parallel()

	proc := newDRWAEventsProcessorWithAuthorizedEmitters([][]byte{[]byte("allowed-emitter")})
	res := proc.processEvent(&argsProcessEvent{
		event: &transaction.Event{
			Identifier: []byte(drwaAssetRegisteredEvent),
			Topics: [][]byte{
				[]byte("HOTEL-1234"),
				[]byte("policy-hotel-1"),
				[]byte("true"),
			},
		},
		logAddress:       []byte("other-emitter"),
		txs:              map[string]*data.Transaction{},
		txHashHexEncoded: "hash",
	})

	require.False(t, res.processed)
	require.Nil(t, res.tokenInfo)
}

func TestDRWAEventsProcessorWithExplicitEmptyEmitterListFailsClosed(t *testing.T) {
	t.Parallel()

	proc := newDRWAEventsProcessorWithAuthorizedEmitters(nil)
	res := proc.processEvent(&argsProcessEvent{
		event: &transaction.Event{
			Identifier: []byte(drwaAssetRegisteredEvent),
			Topics: [][]byte{
				[]byte("HOTEL-1234"),
				[]byte("policy-hotel-1"),
				[]byte("true"),
			},
		},
		logAddress:       []byte("any-emitter"),
		txs:              map[string]*data.Transaction{},
		txHashHexEncoded: "hash",
	})

	require.False(t, res.processed)
	require.Nil(t, res.tokenInfo)
}

func TestDRWAEventsProcessorAcceptsAuthorizedEmitter(t *testing.T) {
	t.Parallel()

	proc := newDRWAEventsProcessorWithAuthorizedEmitters([][]byte{[]byte("allowed-emitter")})
	res := proc.processEvent(&argsProcessEvent{
		event: &transaction.Event{
			Identifier: []byte(drwaAssetRegisteredEvent),
			Topics: [][]byte{
				[]byte("HOTEL-1234"),
				[]byte("policy-hotel-1"),
				[]byte("true"),
			},
		},
		logAddress:       []byte("allowed-emitter"),
		txs:              map[string]*data.Transaction{},
		txHashHexEncoded: "hash",
	})

	require.True(t, res.processed)
	require.NotNil(t, res.tokenInfo)
}

func TestDRWAEventsProcessorBuildsTokenInfoForAssetUpdate(t *testing.T) {
	t.Parallel()

	proc := newTestDRWAEventsProcessorAllowAll()
	res := proc.processEvent(&argsProcessEvent{
		event: &transaction.Event{
			Identifier: []byte(drwaAssetUpdatedEvent),
			Topics: [][]byte{
				[]byte("HOTEL-1234"),
				[]byte("policy-hotel-2"),
			},
		},
		txs:              map[string]*data.Transaction{},
		txHashHexEncoded: "hash",
		blockHash:        "block-hash-asset-update",
		blockRound:       42,
	})

	require.True(t, res.processed)
	require.NotNil(t, res.tokenInfo)
	require.Equal(t, "HOTEL-1234", res.tokenInfo.Token)
	require.Equal(t, "policy-hotel-2", res.tokenInfo.Drwa.PolicyID)
	require.NotNil(t, res.drwaTokenPolicy)
	require.Equal(t, "HOTEL-1234", res.drwaTokenPolicy.TokenID)
	require.Equal(t, "policy-hotel-2", res.drwaTokenPolicy.PolicyID)
	require.Equal(t, drwaAssetUpdatedEvent, res.drwaTokenPolicy.EventType)
	require.Equal(t, "block-hash-asset-update", res.drwaTokenPolicy.BlockHash)
	require.Equal(t, uint64(42), res.drwaTokenPolicy.BlockRound)
	require.False(t, res.drwaTokenPolicy.IsFinalized)
}

func TestDRWAEventsProcessorBuildsTokenInfoForTokenPolicy(t *testing.T) {
	t.Parallel()

	proc := newTestDRWAEventsProcessorAllowAll()
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

func TestDRWAEventsProcessorBuildsTokenInfoForMICAAndWindDownEvents(t *testing.T) {
	t.Parallel()

	proc := newTestDRWAEventsProcessorAllowAll()

	whitePaperRes := proc.processEvent(&argsProcessEvent{
		event: &transaction.Event{
			Identifier: []byte(drwaWhitePaperCidSetEvent),
			Topics: [][]byte{
				[]byte("HOTEL-1234"),
				[]byte("QmTestCidValue1234567890123456789012345678901234"),
			},
		},
		txs:              map[string]*data.Transaction{},
		txHashHexEncoded: "hash-1",
	})

	require.True(t, whitePaperRes.processed)
	require.NotNil(t, whitePaperRes.tokenInfo)
	require.Equal(t, "QmTestCidValue1234567890123456789012345678901234", whitePaperRes.tokenInfo.Drwa.WhitePaperCID)
	require.NotNil(t, whitePaperRes.drwaTokenPolicy)
	require.Equal(t, "QmTestCidValue1234567890123456789012345678901234", whitePaperRes.drwaTokenPolicy.WhitePaperCID)

	registrationRes := proc.processEvent(&argsProcessEvent{
		event: &transaction.Event{
			Identifier: []byte(drwaRegistrationStatusSetEvent),
			Topics: [][]byte{
				[]byte("HOTEL-1234"),
				[]byte("approved"),
			},
		},
		txs:              map[string]*data.Transaction{},
		txHashHexEncoded: "hash-2",
	})

	require.True(t, registrationRes.processed)
	require.NotNil(t, registrationRes.tokenInfo)
	require.Equal(t, "approved", registrationRes.tokenInfo.Drwa.RegistrationStatus)
	require.NotNil(t, registrationRes.drwaTokenPolicy)
	require.Equal(t, "approved", registrationRes.drwaTokenPolicy.RegistrationStatus)

	windDownRes := proc.processEvent(&argsProcessEvent{
		event: &transaction.Event{
			Identifier: []byte(drwaWindDownInitiatedEvent),
			Topics: [][]byte{
				[]byte("HOTEL-1234"),
			},
		},
		txs:              map[string]*data.Transaction{},
		txHashHexEncoded: "hash-3",
	})

	require.True(t, windDownRes.processed)
	require.NotNil(t, windDownRes.tokenInfo)
	require.True(t, windDownRes.tokenInfo.Drwa.WindDownInitiated)
	require.NotNil(t, windDownRes.drwaTokenPolicy)
	require.True(t, windDownRes.drwaTokenPolicy.WindDownInitiated)
}

func TestDRWAEventsProcessorRejectsInvalidMICAProjectionFields(t *testing.T) {
	t.Parallel()

	proc := newTestDRWAEventsProcessorAllowAll()

	invalidCIDRes := proc.processEvent(&argsProcessEvent{
		event: &transaction.Event{
			Identifier: []byte(drwaWhitePaperCidSetEvent),
			Topics: [][]byte{
				[]byte("HOTEL-1234"),
				[]byte("not-a-cid"),
			},
		},
		txs:              map[string]*data.Transaction{},
		txHashHexEncoded: "hash-1",
	})

	require.True(t, invalidCIDRes.processed)
	require.Nil(t, invalidCIDRes.tokenInfo)
	require.Nil(t, invalidCIDRes.drwaTokenPolicy)

	invalidStatusRes := proc.processEvent(&argsProcessEvent{
		event: &transaction.Event{
			Identifier: []byte(drwaRegistrationStatusSetEvent),
			Topics: [][]byte{
				[]byte("HOTEL-1234"),
				[]byte("APPROVED"),
			},
		},
		txs:              map[string]*data.Transaction{},
		txHashHexEncoded: "hash-2",
	})

	require.True(t, invalidStatusRes.processed)
	require.Nil(t, invalidStatusRes.tokenInfo)
	require.Nil(t, invalidStatusRes.drwaTokenPolicy)
}

func TestDRWAEventsProcessorBuildsHolderComplianceRecord(t *testing.T) {
	t.Parallel()

	proc := newTestDRWAEventsProcessorAllowAll()
	res := proc.processEvent(&argsProcessEvent{
		event: &transaction.Event{
			Identifier: []byte(drwaHolderComplianceEvent),
			Topics: [][]byte{
				[]byte("HOTEL-1234"),
				[]byte("erd1holder"),
				{3},
				[]byte("approved"),
				[]byte("clear"),
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
		selfShardID:      2,
		eventOrder:       5,
		blockHash:        "block-hash-holder",
		blockRound:       77,
	})

	require.True(t, res.processed)
	require.NotNil(t, res.drwaHolderCompliance)
	require.Equal(t, "HOTEL-1234", res.drwaHolderCompliance.TokenID)
	require.Equal(t, "erd1holder", res.drwaHolderCompliance.Holder)
	require.Equal(t, uint32(2), res.drwaHolderCompliance.ShardID)
	require.Equal(t, 5, res.drwaHolderCompliance.EventOrder)
	require.Equal(t, uint64(3), res.drwaHolderCompliance.HolderPolicyVersion)
	require.Equal(t, "approved", res.drwaHolderCompliance.KYCStatus)
	require.Equal(t, "clear", res.drwaHolderCompliance.AMLStatus)
	require.Equal(t, "QIB", res.drwaHolderCompliance.InvestorClass)
	require.Equal(t, "US", res.drwaHolderCompliance.JurisdictionCode)
	require.Equal(t, uint64(9), res.drwaHolderCompliance.ExpiryRound)
	require.True(t, res.drwaHolderCompliance.TransferLocked)
	require.False(t, res.drwaHolderCompliance.ReceiveLocked)
	require.NotNil(t, res.drwaHolderCompliance.AuditorAuthorized)
	require.True(t, *res.drwaHolderCompliance.AuditorAuthorized)
	require.Equal(t, "block-hash-holder", res.drwaHolderCompliance.BlockHash)
	require.Equal(t, uint64(77), res.drwaHolderCompliance.BlockRound)
	require.False(t, res.drwaHolderCompliance.IsFinalized)
}

func TestDRWAEventsProcessorRejectsInvalidHolderComplianceProjectionFields(t *testing.T) {
	t.Parallel()

	proc := newTestDRWAEventsProcessorAllowAll()

	invalidStatus := proc.processEvent(&argsProcessEvent{
		event: &transaction.Event{
			Identifier: []byte(drwaHolderComplianceEvent),
			Topics: [][]byte{
				[]byte("HOTEL-1234"),
				[]byte("erd1holder"),
				{3},
				[]byte("APPROVED"),
				[]byte("clear"),
			},
		},
		txs:              map[string]*data.Transaction{},
		txHashHexEncoded: "hash-1",
	})

	require.True(t, invalidStatus.processed)
	require.Nil(t, invalidStatus.drwaHolderCompliance)

	invalidInvestorClass := proc.processEvent(&argsProcessEvent{
		event: &transaction.Event{
			Identifier: []byte(drwaHolderComplianceEvent),
			Topics: [][]byte{
				[]byte("HOTEL-1234"),
				[]byte("erd1holder"),
				{3},
				[]byte("approved"),
				[]byte("clear"),
				[]byte("QIB bad"),
			},
		},
		txs:              map[string]*data.Transaction{},
		txHashHexEncoded: "hash-2",
	})

	require.True(t, invalidInvestorClass.processed)
	require.Nil(t, invalidInvestorClass.drwaHolderCompliance)
}

func TestDRWAEventsProcessorBuildsIdentityRecord(t *testing.T) {
	t.Parallel()

	proc := newTestDRWAEventsProcessorAllowAll()

	registered := proc.processEvent(&argsProcessEvent{
		event: &transaction.Event{
			Identifier: []byte(drwaIdentityRegisteredEvent),
			Topics: [][]byte{
				[]byte("erd1subject"),
				[]byte("US"),
				[]byte("company"),
			},
		},
		txs:              map[string]*data.Transaction{},
		txHashHexEncoded: "hash-1",
		selfShardID:      2,
		eventOrder:       4,
		blockHash:        "block-hash-identity",
		blockRound:       88,
	})

	require.True(t, registered.processed)
	require.NotNil(t, registered.drwaIdentity)
	require.Equal(t, "erd1subject", registered.drwaIdentity.Subject)
	require.Equal(t, drwaIdentityRegisteredEvent, registered.drwaIdentity.EventType)
	require.Equal(t, "US", registered.drwaIdentity.JurisdictionCode)
	require.Equal(t, "company", registered.drwaIdentity.EntityType)
	require.Equal(t, uint32(2), registered.drwaIdentity.ShardID)
	require.Equal(t, 4, registered.drwaIdentity.EventOrder)
	require.Equal(t, "block-hash-identity", registered.drwaIdentity.BlockHash)
	require.Equal(t, uint64(88), registered.drwaIdentity.BlockRound)
	require.False(t, registered.drwaIdentity.IsFinalized)

	updated := proc.processEvent(&argsProcessEvent{
		event: &transaction.Event{
			Identifier: []byte(drwaComplianceUpdatedEvent),
			Topics: [][]byte{
				[]byte("erd1subject"),
				[]byte("approved"),
				[]byte("clear"),
			},
		},
		txs:              map[string]*data.Transaction{},
		txHashHexEncoded: "hash-2",
	})

	require.True(t, updated.processed)
	require.NotNil(t, updated.drwaIdentity)
	require.Equal(t, "approved", updated.drwaIdentity.KYCStatus)
	require.Equal(t, "clear", updated.drwaIdentity.AMLStatus)
}

func TestDRWAEventsProcessorRejectsInvalidComplianceUpdatedProjectionFields(t *testing.T) {
	t.Parallel()

	proc := newTestDRWAEventsProcessorAllowAll()
	res := proc.processEvent(&argsProcessEvent{
		event: &transaction.Event{
			Identifier: []byte(drwaComplianceUpdatedEvent),
			Topics: [][]byte{
				[]byte("erd1subject"),
				[]byte("approved "),
				[]byte("clear"),
			},
		},
		txs:              map[string]*data.Transaction{},
		txHashHexEncoded: "hash-1",
	})

	require.True(t, res.processed)
	require.Nil(t, res.drwaIdentity)
}

func TestDRWAEventsProcessorBuildsAttestationRecord(t *testing.T) {
	t.Parallel()

	proc := newTestDRWAEventsProcessorAllowAll()
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
		selfShardID:      1,
		eventOrder:       3,
		blockHash:        "block-hash-attestation",
		blockRound:       91,
	})

	require.True(t, res.processed)
	require.NotNil(t, res.drwaAttestation)
	require.Equal(t, "HOTEL-1234", res.drwaAttestation.TokenID)
	require.Equal(t, "erd1subject", res.drwaAttestation.Subject)
	require.Equal(t, "erd1auditor", res.drwaAttestation.Auditor)
	require.Equal(t, drwaAttestationRecordedEvent, res.drwaAttestation.EventType)
	require.Equal(t, "kyc", res.drwaAttestation.AttestationType)
	require.Equal(t, uint32(1), res.drwaAttestation.ShardID)
	require.Equal(t, 3, res.drwaAttestation.EventOrder)
	require.True(t, res.drwaAttestation.Approved)
	require.Equal(t, uint64(7), res.drwaAttestation.AttestedRound)
	require.Equal(t, "block-hash-attestation", res.drwaAttestation.BlockHash)
	require.Equal(t, uint64(91), res.drwaAttestation.BlockRound)
	require.False(t, res.drwaAttestation.IsFinalized)
}

func TestDRWAEventsProcessorBuildsAttestationOverwriteRecord(t *testing.T) {
	t.Parallel()

	proc := newTestDRWAEventsProcessorAllowAll()
	res := proc.processEvent(&argsProcessEvent{
		event: &transaction.Event{
			Identifier: []byte(drwaAttestationOverwrittenEvent),
			Topics: [][]byte{
				[]byte("HOTEL-1234"),
				[]byte("erd1subject"),
				[]byte("erd1auditor"),
			},
		},
		txs:              map[string]*data.Transaction{},
		txHashHexEncoded: "hash",
		selfShardID:      1,
		eventOrder:       8,
	})

	require.True(t, res.processed)
	require.NotNil(t, res.drwaAttestation)
	require.Equal(t, "HOTEL-1234", res.drwaAttestation.TokenID)
	require.Equal(t, "erd1subject", res.drwaAttestation.Subject)
	require.Equal(t, "erd1auditor", res.drwaAttestation.Auditor)
	require.Equal(t, drwaAttestationOverwrittenEvent, res.drwaAttestation.EventType)
	require.Equal(t, uint32(1), res.drwaAttestation.ShardID)
	require.Equal(t, 8, res.drwaAttestation.EventOrder)
}

func TestDRWAEventsProcessorBuildsAuditorRevokedRecord(t *testing.T) {
	t.Parallel()

	proc := newTestDRWAEventsProcessorAllowAll()
	res := proc.processEvent(&argsProcessEvent{
		event: &transaction.Event{
			Identifier: []byte(drwaAuditorRevokedEvent),
			Topics: [][]byte{
				[]byte("erd1auditor"),
			},
		},
		txs:              map[string]*data.Transaction{},
		txHashHexEncoded: "hash",
		selfShardID:      2,
		eventOrder:       11,
	})

	require.True(t, res.processed)
	require.NotNil(t, res.drwaAttestation)
	require.Equal(t, drwaAuditorRevokedEvent, res.drwaAttestation.EventType)
	require.Equal(t, "erd1auditor", res.drwaAttestation.Auditor)
	require.Equal(t, uint32(2), res.drwaAttestation.ShardID)
	require.Equal(t, 11, res.drwaAttestation.EventOrder)
}

func TestDRWAEventsProcessorBuildsDenialRecordWithShardIDAndEventOrder(t *testing.T) {
	t.Parallel()

	proc := newTestDRWAEventsProcessorAllowAll()
	res := proc.processEvent(&argsProcessEvent{
		event: &transaction.Event{
			Identifier: []byte(drwaTransferDeniedEvent),
			Topics: [][]byte{
				[]byte("HOTEL-1234"),
				[]byte(coredrwa.DenialAMLBlockedSender),
				[]byte("erd1sender"),
				[]byte("erd1receiver"),
			},
		},
		txs:              map[string]*data.Transaction{},
		txHashHexEncoded: "hash",
		selfShardID:      7,
		eventOrder:       9,
		blockHash:        "block-hash-denial",
		blockRound:       105,
	})

	require.True(t, res.processed)
	require.NotNil(t, res.drwaDenial)
	require.Equal(t, uint32(7), res.drwaDenial.ShardID)
	require.Equal(t, 9, res.drwaDenial.EventOrder)
	require.Equal(t, string(coredrwa.DenialAMLBlockedSender), res.drwaDenial.DenialCode)
	require.Equal(t, "block-hash-denial", res.drwaDenial.BlockHash)
	require.Equal(t, uint64(105), res.drwaDenial.BlockRound)
	require.False(t, res.drwaDenial.IsFinalized)
}

func TestDRWAEventsProcessorNormalizesDenialCodeToCanonicalSharedValue(t *testing.T) {
	t.Parallel()

	proc := newTestDRWAEventsProcessorAllowAll()
	res := proc.processEvent(&argsProcessEvent{
		event: &transaction.Event{
			Identifier: []byte(drwaTransferDeniedEvent),
			Topics: [][]byte{
				[]byte("HOTEL-1234"),
				[]byte("  drwa_kyc_required_sender  "),
			},
		},
		txs:              map[string]*data.Transaction{},
		txHashHexEncoded: "hash",
	})

	require.True(t, res.processed)
	require.NotNil(t, res.drwaDenial)
	require.Equal(t, "DRWA_KYC_REQUIRED_SENDER", res.drwaDenial.DenialCode)
}

func TestNormalizeDRWADenialCode_PreservesUnknownValueAfterTrim(t *testing.T) {
	t.Parallel()

	require.Equal(t, string(coredrwa.DenialUnknown), normalizeDRWADenialCode([]byte("  DRWA_UNKNOWN_REASON  ")))
}

func TestDRWAEventsProcessorProcessesGovernanceEvents(t *testing.T) {
	t.Parallel()

	proc := newTestDRWAEventsProcessorAllowAll()
	for _, identifier := range []string{
		drwaGovernanceProposedEvent,
		drwaGovernanceAcceptedEvent,
		drwaGovernanceRevokedEvent,
	} {
		res := proc.processEvent(&argsProcessEvent{
			event: &transaction.Event{
				Identifier: []byte(identifier),
				Topics:     [][]byte{[]byte("erd1governance")},
			},
			txs:              map[string]*data.Transaction{},
			txHashHexEncoded: "hash",
			selfShardID:      4,
			eventOrder:       2,
			blockHash:        "block-hash-governance",
			blockRound:       123,
		})
		require.True(t, res.processed)
		require.NotNil(t, res.drwaControlEvent)
		require.Equal(t, "erd1governance", res.drwaControlEvent.Governance)
		require.Equal(t, uint32(4), res.drwaControlEvent.ShardID)
		require.Equal(t, "block-hash-governance", res.drwaControlEvent.BlockHash)
		require.Equal(t, uint64(123), res.drwaControlEvent.BlockRound)
		require.False(t, res.drwaControlEvent.IsFinalized)
	}
}

func TestDRWAEventsProcessorProcessesAuthAdminAuditEvents(t *testing.T) {
	t.Parallel()

	proc := newTestDRWAEventsProcessorAllowAll()
	identifiers := []string{
		drwaAuthActionProposedEvent,
		drwaAuthActionSignedEvent,
		drwaAuthActionUnsignedEvent,
		drwaAuthActionDiscardedEvent,
		drwaAuthActionPerformedEvent,
		drwaAuthorizedCallerUpdatedEvent,
		drwaSignerAddedEvent,
		drwaSignerRemovedEvent,
		drwaSignerReplacedEvent,
		drwaQuorumChangedEvent,
	}

	for _, identifier := range identifiers {
		res := proc.processEvent(&argsProcessEvent{
			event: &transaction.Event{
				Identifier: []byte(identifier),
				Topics: [][]byte{
					[]byte("action-or-subject"),
					[]byte("erd1signer"),
				},
			},
			txs:              map[string]*data.Transaction{},
			txHashHexEncoded: "hash",
			selfShardID:      5,
			eventOrder:       9,
			blockHash:        "block-hash-auth-admin",
			blockRound:       456,
		})

		require.True(t, res.processed, identifier)
		require.NotNil(t, res.drwaControlEvent, identifier)
		require.Equal(t, identifier, res.drwaControlEvent.EventType)
		require.Equal(t, uint32(5), res.drwaControlEvent.ShardID)
		require.Equal(t, 9, res.drwaControlEvent.EventOrder)
		require.Equal(t, "block-hash-auth-admin", res.drwaControlEvent.BlockHash)
		require.Equal(t, uint64(456), res.drwaControlEvent.BlockRound)
		require.Len(t, res.drwaControlEvent.Topics, 2)
	}
}

func TestDRWAEventsProcessorProcessesExtendedCanonicalEvents(t *testing.T) {
	t.Parallel()

	proc := newTestDRWAEventsProcessorAllowAll()
	identifiers := []string{
		drwaWhitePaperCidSetEvent,
		drwaRegistrationStatusSetEvent,
		drwaIdentityRegisteredEvent,
		drwaComplianceUpdatedEvent,
		drwaIdentityDeactivatedEvent,
		drwaIdentityErasedEvent,
		drwaWindDownInitiatedEvent,
		drwaAuditorRevokedEvent,
		drwaAttestationOverwrittenEvent,
	}

	for _, identifier := range identifiers {
		res := proc.processEvent(&argsProcessEvent{
			event: &transaction.Event{
				Identifier: []byte(identifier),
			},
			txs:              map[string]*data.Transaction{},
			txHashHexEncoded: "hash",
		})

		require.True(t, res.processed, identifier)
	}
}

func TestDRWAEventsProcessorBuildsControlEventForTransferAllowed(t *testing.T) {
	t.Parallel()

	proc := newTestDRWAEventsProcessorAllowAll()
	res := proc.processEvent(&argsProcessEvent{
		event: &transaction.Event{
			Identifier: []byte(drwaTransferAllowedEvent),
			Topics: [][]byte{
				[]byte("HOTEL-1234"),
				[]byte("erd1sender"),
				[]byte("erd1receiver"),
			},
		},
		txs:              map[string]*data.Transaction{},
		txHashHexEncoded: "hash",
		selfShardID:      6,
		eventOrder:       7,
	})

	require.True(t, res.processed)
	require.NotNil(t, res.drwaControlEvent)
	require.Equal(t, drwaTransferAllowedEvent, res.drwaControlEvent.EventType)
	require.Len(t, res.drwaControlEvent.Topics, 3)
	require.Equal(t, uint32(6), res.drwaControlEvent.ShardID)
	require.Equal(t, 7, res.drwaControlEvent.EventOrder)
}

func TestDRWAEventsProcessorBuildsControlEventForMetadataProtection(t *testing.T) {
	t.Parallel()

	proc := newTestDRWAEventsProcessorAllowAll()
	res := proc.processEvent(&argsProcessEvent{
		event: &transaction.Event{
			Identifier: []byte(drwaMetadataProtectionEvent),
			Topics: [][]byte{
				[]byte("HOTEL-1234"),
				[]byte("enabled"),
			},
		},
		txs:              map[string]*data.Transaction{},
		txHashHexEncoded: "hash",
	})

	require.True(t, res.processed)
	require.NotNil(t, res.drwaControlEvent)
	require.Equal(t, drwaMetadataProtectionEvent, res.drwaControlEvent.EventType)
	require.Len(t, res.drwaControlEvent.Topics, 2)
}

func TestDRWAEventsProcessorProcessesAuditorLifecycleEvents(t *testing.T) {
	t.Parallel()

	proc := newTestDRWAEventsProcessorAllowAll()
	for _, identifier := range []string{
		drwaAuditorProposedEvent,
		drwaAuditorAcceptedEvent,
		drwaAttestationRecordedEvent,
	} {
		res := proc.processEvent(&argsProcessEvent{
			event:            &transaction.Event{Identifier: []byte(identifier)},
			txs:              map[string]*data.Transaction{},
			txHashHexEncoded: "hash",
		})
		require.True(t, res.processed)
	}
}
