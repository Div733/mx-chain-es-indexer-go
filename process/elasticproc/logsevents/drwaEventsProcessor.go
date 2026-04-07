package logsevents

import (
	"math/big"
	"strings"

	"github.com/multiversx/mx-chain-es-indexer-go/data"
)

const (
	drwaAssetRegisteredEvent    = "drwaAssetRegistered"
	drwaTokenPolicyEvent        = "drwaTokenPolicy"
	drwaHolderComplianceEvent   = "drwaHolderCompliance"
	drwaTransferDeniedEvent     = "drwaTransferDenied"
	drwaTransferAllowedEvent    = "drwaTransferAllowed"
	drwaGlobalPauseEvent        = "drwaGlobalPause"
	drwaMetadataProtectionEvent = "drwaMetadataProtection"
	drwaAuditorProposedEvent    = "drwaAuditorProposed"
	drwaAuditorAcceptedEvent    = "drwaAuditorAccepted"
	drwaAttestationRecordedEvent = "drwaAttestationRecorded"
	drwaGovernanceProposedEvent = "drwaGovernanceProposed"
	drwaGovernanceAcceptedEvent = "drwaGovernanceAccepted"
)

type drwaEventsProcessor struct{}

func newDRWAEventsProcessor() *drwaEventsProcessor {
	return &drwaEventsProcessor{}
}

// IsInterfaceNil returns true if there is no value under the interface
func (dep *drwaEventsProcessor) IsInterfaceNil() bool {
	return dep == nil
}

func (dep *drwaEventsProcessor) processEvent(args *argsProcessEvent) argOutputProcessEvent {
	identifier := string(args.event.GetIdentifier())
	if !strings.HasPrefix(strings.ToLower(identifier), "drwa") {
		return argOutputProcessEvent{}
	}

	tokenInfo := dep.tryBuildTokenInfo(identifier, args)
	tokenPolicy := dep.tryBuildTokenPolicyRecord(identifier, args)
	denial := dep.tryBuildDenialRecord(identifier, args)
	holderCompliance := dep.tryBuildHolderComplianceRecord(identifier, args)
	attestation := dep.tryBuildAttestationRecord(identifier, args)

	tx, ok := args.txs[args.txHashHexEncoded]
	if ok {
		tx.HasOperations = true
		tx.Operation = "drwa"
		tx.Function = identifier
		return argOutputProcessEvent{
			processed:            true,
			tokenInfo:            tokenInfo,
			drwaTokenPolicy:      tokenPolicy,
			drwaDenial:           denial,
			drwaHolderCompliance: holderCompliance,
			drwaAttestation:      attestation,
		}
	}

	scr, ok := args.scrs[args.txHashHexEncoded]
	if ok {
		scr.HasOperations = true
		scr.Operation = "drwa"
		scr.Function = identifier
		return argOutputProcessEvent{
			processed:            true,
			tokenInfo:            tokenInfo,
			drwaTokenPolicy:      tokenPolicy,
			drwaDenial:           denial,
			drwaHolderCompliance: holderCompliance,
			drwaAttestation:      attestation,
		}
	}

	return argOutputProcessEvent{
		processed:            true,
		tokenInfo:            tokenInfo,
		drwaTokenPolicy:      tokenPolicy,
		drwaDenial:           denial,
		drwaHolderCompliance: holderCompliance,
		drwaAttestation:      attestation,
	}
}

func (dep *drwaEventsProcessor) tryBuildTokenInfo(identifier string, args *argsProcessEvent) *data.TokenInfo {
	topics := args.event.GetTopics()
	switch identifier {
	case drwaAssetRegisteredEvent:
		if len(topics) < 3 {
			return nil
		}

		return &data.TokenInfo{
			Token: string(topics[0]),
			Drwa: &data.DrwaTokenInfo{
				Regulated: bytesToBool(topics[2]),
				PolicyID:  string(topics[1]),
			},
			DrwaUpdate: true,
		}
	case drwaTokenPolicyEvent:
		if len(topics) < 5 {
			return nil
		}

		return &data.TokenInfo{
			Token: string(topics[0]),
			Drwa: &data.DrwaTokenInfo{
				Regulated:          bytesToBool(topics[1]),
				GlobalPause:        bytesToBool(topics[2]),
				StrictAuditorMode:  bytesToBool(topics[3]),
				TokenPolicyVersion: big.NewInt(0).SetBytes(topics[4]).Uint64(),
			},
			DrwaUpdate: true,
		}
	case drwaGlobalPauseEvent:
		if len(topics) < 2 {
			return nil
		}

		return &data.TokenInfo{
			Token: string(topics[0]),
			Drwa: &data.DrwaTokenInfo{
				GlobalPause: bytesToBool(topics[1]),
			},
			DrwaUpdate: true,
		}
	default:
		return nil
	}
}

func (dep *drwaEventsProcessor) tryBuildTokenPolicyRecord(identifier string, args *argsProcessEvent) *data.DrwaTokenPolicyRecord {
	topics := args.event.GetTopics()
	switch identifier {
	case drwaAssetRegisteredEvent:
		if len(topics) < 3 {
			return nil
		}

		return &data.DrwaTokenPolicyRecord{
			TxHash:     args.txHashHexEncoded,
			TokenID:    string(topics[0]),
			EventType:  identifier,
			PolicyID:   string(topics[1]),
			Regulated:  bytesToBool(topics[2]),
			Timestamp:  args.timestamp,
			TimestampMs: args.timestampMs,
		}
	case drwaTokenPolicyEvent:
		if len(topics) < 5 {
			return nil
		}

		return &data.DrwaTokenPolicyRecord{
			TxHash:             args.txHashHexEncoded,
			TokenID:            string(topics[0]),
			EventType:          identifier,
			Regulated:          bytesToBool(topics[1]),
			GlobalPause:        bytesToBool(topics[2]),
			StrictAuditorMode:  bytesToBool(topics[3]),
			TokenPolicyVersion: big.NewInt(0).SetBytes(topics[4]).Uint64(),
			Timestamp:          args.timestamp,
			TimestampMs:        args.timestampMs,
		}
	case drwaGlobalPauseEvent:
		if len(topics) < 2 {
			return nil
		}

		return &data.DrwaTokenPolicyRecord{
			TxHash:      args.txHashHexEncoded,
			TokenID:     string(topics[0]),
			EventType:   identifier,
			GlobalPause: bytesToBool(topics[1]),
			Timestamp:   args.timestamp,
			TimestampMs: args.timestampMs,
		}
	default:
		return nil
	}
}

func (dep *drwaEventsProcessor) tryBuildDenialRecord(identifier string, args *argsProcessEvent) *data.DrwaDenialRecord {
	if identifier != drwaTransferDeniedEvent {
		return nil
	}

	topics := args.event.GetTopics()
	if len(topics) < 2 {
		return nil
	}

	record := &data.DrwaDenialRecord{
		TxHash:      args.txHashHexEncoded,
		TokenID:     string(topics[0]),
		DenialCode:  string(topics[1]),
		Timestamp:   args.timestamp,
		TimestampMs: args.timestampMs,
	}
	if len(topics) >= 3 {
		record.Sender = string(topics[2])
	}
	if len(topics) >= 4 {
		record.Receiver = string(topics[3])
	}

	return record
}

func (dep *drwaEventsProcessor) tryBuildHolderComplianceRecord(identifier string, args *argsProcessEvent) *data.DrwaHolderComplianceRecord {
	if identifier != drwaHolderComplianceEvent {
		return nil
	}

	topics := args.event.GetTopics()
	if len(topics) < 2 {
		return nil
	}

	record := &data.DrwaHolderComplianceRecord{
		TxHash:      args.txHashHexEncoded,
		TokenID:     string(topics[0]),
		Holder:      string(topics[1]),
		Timestamp:   args.timestamp,
		TimestampMs: args.timestampMs,
	}
	if len(topics) >= 3 {
		record.HolderPolicyVersion = big.NewInt(0).SetBytes(topics[2]).Uint64()
	}
	if len(topics) >= 4 {
		record.KYCStatus = string(topics[3])
	}
	if len(topics) >= 5 {
		record.AMLStatus = string(topics[4])
	}
	if len(topics) >= 6 {
		record.InvestorClass = string(topics[5])
	}
	if len(topics) >= 7 {
		record.JurisdictionCode = string(topics[6])
	}
	if len(topics) >= 8 {
		record.ExpiryRound = big.NewInt(0).SetBytes(topics[7]).Uint64()
	}
	if len(topics) >= 9 {
		record.TransferLocked = bytesToBool(topics[8])
	}
	if len(topics) >= 10 {
		record.ReceiveLocked = bytesToBool(topics[9])
	}
	if len(topics) >= 11 {
		record.AuditorAuthorized = bytesToBool(topics[10])
	}

	return record
}

func (dep *drwaEventsProcessor) tryBuildAttestationRecord(identifier string, args *argsProcessEvent) *data.DrwaAttestationRecord {
	if identifier != drwaAuditorAcceptedEvent && identifier != drwaAuditorProposedEvent && identifier != drwaAttestationRecordedEvent {
		return nil
	}

	topics := args.event.GetTopics()
	if len(topics) < 1 {
		return nil
	}

	record := &data.DrwaAttestationRecord{
		TxHash:      args.txHashHexEncoded,
		EventType:   identifier,
		Timestamp:   args.timestamp,
		TimestampMs: args.timestampMs,
	}

	if identifier == drwaAttestationRecordedEvent {
		if len(topics) < 6 {
			return nil
		}

		record.TokenID = string(topics[0])
		record.Subject = string(topics[1])
		record.Auditor = string(topics[2])
		record.Approved = bytesToBool(topics[4])
		record.AttestedRound = big.NewInt(0).SetBytes(topics[5]).Uint64()
		return record
	}

	record.Auditor = string(topics[0])
	return record
}
