package logsevents

import (
	"encoding/hex"
	"math/big"
	"strings"

	coredrwa "github.com/multiversx/mx-chain-core-go/data/drwa"
	"github.com/multiversx/mx-chain-es-indexer-go/data"
)

const (
	drwaAssetRegisteredEvent        = "drwaAssetRegistered"
	drwaAssetUpdatedEvent           = "drwaAssetUpdated"
	drwaTokenPolicyEvent            = "drwaTokenPolicy"
	drwaHolderComplianceEvent       = "drwaHolderCompliance"
	drwaTransferDeniedEvent         = "drwaTransferDenied"
	drwaTransferAllowedEvent        = "drwaTransferAllowed"
	drwaGlobalPauseEvent            = "drwaGlobalPause"
	drwaMetadataProtectionEvent     = "drwaMetadataProtection"
	drwaWhitePaperCidSetEvent       = "drwaWhitePaperCidSet"
	drwaRegistrationStatusSetEvent  = "drwaRegistrationStatusSet"
	drwaIdentityRegisteredEvent     = "drwaIdentityRegistered"
	drwaComplianceUpdatedEvent      = "drwaComplianceUpdated"
	drwaIdentityDeactivatedEvent    = "drwaIdentityDeactivated"
	drwaIdentityErasedEvent         = "drwaIdentityErased"
	drwaWindDownInitiatedEvent      = "drwaWindDownInitiated"
	drwaAuditorProposedEvent        = "drwaAuditorProposed"
	drwaAuditorAcceptedEvent        = "drwaAuditorAccepted"
	drwaAuditorRevokedEvent         = "drwaAuditorRevoked"
	drwaAttestationOverwrittenEvent = "drwaAttestationOverwritten"
	drwaAttestationRecordedEvent    = "drwaAttestationRecorded"
	drwaGovernanceProposedEvent     = "drwaGovernanceProposed"
	drwaGovernanceAcceptedEvent     = "drwaGovernanceAccepted"
	drwaGovernanceRevokedEvent      = "drwaGovernanceRevoked"
)

// drwaCanonicalEventsMap is the exact allow-list of DRWA event identifiers
// (lowercased).  Only events in this map are processed — prefix matching is
// intentionally avoided so that arbitrary contracts cannot pollute the
// compliance index by emitting events whose identifier starts with "drwa".
var drwaCanonicalEventsMap map[string]struct{}
var drwaCanonicalDenialCodes map[string]string

func init() {
	drwaCanonicalEventsMap = map[string]struct{}{
		strings.ToLower(drwaAssetRegisteredEvent):        {},
		strings.ToLower(drwaAssetUpdatedEvent):           {},
		strings.ToLower(drwaTokenPolicyEvent):            {},
		strings.ToLower(drwaHolderComplianceEvent):       {},
		strings.ToLower(drwaTransferDeniedEvent):         {},
		strings.ToLower(drwaTransferAllowedEvent):        {},
		strings.ToLower(drwaGlobalPauseEvent):            {},
		strings.ToLower(drwaMetadataProtectionEvent):     {},
		strings.ToLower(drwaWhitePaperCidSetEvent):       {},
		strings.ToLower(drwaRegistrationStatusSetEvent):  {},
		strings.ToLower(drwaIdentityRegisteredEvent):     {},
		strings.ToLower(drwaComplianceUpdatedEvent):      {},
		strings.ToLower(drwaIdentityDeactivatedEvent):    {},
		strings.ToLower(drwaIdentityErasedEvent):         {},
		strings.ToLower(drwaWindDownInitiatedEvent):      {},
		strings.ToLower(drwaAuditorProposedEvent):        {},
		strings.ToLower(drwaAuditorAcceptedEvent):        {},
		strings.ToLower(drwaAuditorRevokedEvent):         {},
		strings.ToLower(drwaAttestationOverwrittenEvent): {},
		strings.ToLower(drwaAttestationRecordedEvent):    {},
		strings.ToLower(drwaGovernanceProposedEvent):     {},
		strings.ToLower(drwaGovernanceAcceptedEvent):     {},
		strings.ToLower(drwaGovernanceRevokedEvent):      {},
	}

	drwaCanonicalDenialCodes = map[string]string{
		string(coredrwa.DenialPolicyNotSynced):     string(coredrwa.DenialPolicyNotSynced),
		string(coredrwa.DenialTokenPaused):         string(coredrwa.DenialTokenPaused),
		string(coredrwa.DenialKYCRequiredSender):   string(coredrwa.DenialKYCRequiredSender),
		string(coredrwa.DenialAMLBlockedSender):    string(coredrwa.DenialAMLBlockedSender),
		string(coredrwa.DenialAssetExpired):        string(coredrwa.DenialAssetExpired),
		string(coredrwa.DenialTransferLocked):      string(coredrwa.DenialTransferLocked),
		string(coredrwa.DenialKYCRequiredReceiver): string(coredrwa.DenialKYCRequiredReceiver),
		string(coredrwa.DenialAMLBlockedReceiver):  string(coredrwa.DenialAMLBlockedReceiver),
		string(coredrwa.DenialReceiveLocked):       string(coredrwa.DenialReceiveLocked),
		string(coredrwa.DenialInvestorClass):       string(coredrwa.DenialInvestorClass),
		string(coredrwa.DenialJurisdiction):        string(coredrwa.DenialJurisdiction),
		string(coredrwa.DenialAuditorRequired):     string(coredrwa.DenialAuditorRequired),
		string(coredrwa.DenialTravelRuleRequired):  string(coredrwa.DenialTravelRuleRequired),
		string(coredrwa.DenialSanctionsMatch):      string(coredrwa.DenialSanctionsMatch),
		string(coredrwa.DenialWindDownActive):      string(coredrwa.DenialWindDownActive),
	}
}

type drwaEventsProcessor struct {
	drwaRegistryAddress string
}

func newDRWAEventsProcessor(registryAddress string) *drwaEventsProcessor {
	return &drwaEventsProcessor{drwaRegistryAddress: registryAddress}
}

// IsInterfaceNil returns true if there is no value under the interface
func (dep *drwaEventsProcessor) IsInterfaceNil() bool {
	return dep == nil
}

func (dep *drwaEventsProcessor) processEvent(args *argsProcessEvent) argOutputProcessEvent {
	identifier := string(args.event.GetIdentifier())
	if _, ok := drwaCanonicalEventsMap[strings.ToLower(identifier)]; !ok {
		return argOutputProcessEvent{}
	}

	if dep.drwaRegistryAddress != "" {
		emitterHex := hex.EncodeToString(args.logAddress)
		if emitterHex != dep.drwaRegistryAddress {
			return argOutputProcessEvent{}
		}
	}

	tokenInfo := dep.tryBuildTokenInfo(identifier, args)
	identity := dep.tryBuildIdentityRecord(identifier, args)
	tokenPolicy := dep.tryBuildTokenPolicyRecord(identifier, args)
	denial := dep.tryBuildDenialRecord(identifier, args)
	holderCompliance := dep.tryBuildHolderComplianceRecord(identifier, args)
	attestation := dep.tryBuildAttestationRecord(identifier, args)
	controlEvent := dep.tryBuildControlEventRecord(identifier, args)

	tx, ok := args.txs[args.txHashHexEncoded]
	if ok {
		tx.HasOperations = true
		tx.Operation = "drwa"
		tx.Function = identifier
		return argOutputProcessEvent{
			processed:            true,
			tokenInfo:            tokenInfo,
			drwaIdentity:         identity,
			drwaTokenPolicy:      tokenPolicy,
			drwaDenial:           denial,
			drwaHolderCompliance: holderCompliance,
			drwaAttestation:      attestation,
			drwaControlEvent:     controlEvent,
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
			drwaIdentity:         identity,
			drwaTokenPolicy:      tokenPolicy,
			drwaDenial:           denial,
			drwaHolderCompliance: holderCompliance,
			drwaAttestation:      attestation,
			drwaControlEvent:     controlEvent,
		}
	}

	return argOutputProcessEvent{
		processed:            true,
		tokenInfo:            tokenInfo,
		drwaIdentity:         identity,
		drwaTokenPolicy:      tokenPolicy,
		drwaDenial:           denial,
		drwaHolderCompliance: holderCompliance,
		drwaAttestation:      attestation,
		drwaControlEvent:     controlEvent,
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
	case drwaAssetUpdatedEvent:
		if len(topics) < 2 {
			return nil
		}

		return &data.TokenInfo{
			Token: string(topics[0]),
			Drwa: &data.DrwaTokenInfo{
				PolicyID: string(topics[1]),
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
	case drwaWhitePaperCidSetEvent:
		if len(topics) < 2 {
			return nil
		}

		return &data.TokenInfo{
			Token: string(topics[0]),
			Drwa: &data.DrwaTokenInfo{
				WhitePaperCID: string(topics[1]),
			},
			DrwaUpdate: true,
		}
	case drwaRegistrationStatusSetEvent:
		if len(topics) < 2 {
			return nil
		}

		return &data.TokenInfo{
			Token: string(topics[0]),
			Drwa: &data.DrwaTokenInfo{
				RegistrationStatus: string(topics[1]),
			},
			DrwaUpdate: true,
		}
	case drwaWindDownInitiatedEvent:
		if len(topics) < 1 {
			return nil
		}

		return &data.TokenInfo{
			Token: string(topics[0]),
			Drwa: &data.DrwaTokenInfo{
				WindDownInitiated: true,
			},
			DrwaUpdate: true,
		}
	default:
		return nil
	}
}

func (dep *drwaEventsProcessor) tryBuildIdentityRecord(identifier string, args *argsProcessEvent) *data.DrwaIdentityRecord {
	switch identifier {
	case drwaIdentityRegisteredEvent, drwaComplianceUpdatedEvent, drwaIdentityDeactivatedEvent, drwaIdentityErasedEvent:
	default:
		return nil
	}

	topics := args.event.GetTopics()
	if len(topics) < 1 {
		return nil
	}

	record := &data.DrwaIdentityRecord{
		TxHash:      args.txHashHexEncoded,
		Subject:     string(topics[0]),
		EventType:   identifier,
		BlockHash:   args.blockHash,
		BlockRound:  args.blockRound,
		IsFinalized: false,
		ShardID:     args.selfShardID,
		EventOrder:  args.eventOrder,
		Timestamp:   args.timestamp,
		TimestampMs: args.timestampMs,
	}

	switch identifier {
	case drwaIdentityRegisteredEvent:
		if len(topics) < 3 {
			return nil
		}
		record.JurisdictionCode = validateJurisdictionCode(topics[1])
		record.EntityType = validateFieldLength(topics[2], 64)
	case drwaComplianceUpdatedEvent:
		if len(topics) < 3 {
			return nil
		}
		record.KYCStatus = validateComplianceStatus(topics[1])
		record.AMLStatus = validateComplianceStatus(topics[2])
	}

	return record
}

func (dep *drwaEventsProcessor) tryBuildTokenPolicyRecord(identifier string, args *argsProcessEvent) *data.DrwaTokenPolicyRecord {
	topics := args.event.GetTopics()
	switch identifier {
	case drwaAssetRegisteredEvent:
		if len(topics) < 3 {
			return nil
		}

		return &data.DrwaTokenPolicyRecord{
			TxHash:      args.txHashHexEncoded,
			TokenID:     string(topics[0]),
			EventType:   identifier,
			BlockHash:   args.blockHash,
			BlockRound:  args.blockRound,
			IsFinalized: false,
			ShardID:     args.selfShardID,
			EventOrder:  args.eventOrder,
			PolicyID:    string(topics[1]),
			Regulated:   bytesToBool(topics[2]),
			Timestamp:   args.timestamp,
			TimestampMs: args.timestampMs,
		}
	case drwaAssetUpdatedEvent:
		if len(topics) < 2 {
			return nil
		}

		return &data.DrwaTokenPolicyRecord{
			TxHash:      args.txHashHexEncoded,
			TokenID:     string(topics[0]),
			EventType:   identifier,
			BlockHash:   args.blockHash,
			BlockRound:  args.blockRound,
			IsFinalized: false,
			ShardID:     args.selfShardID,
			EventOrder:  args.eventOrder,
			PolicyID:    string(topics[1]),
			Timestamp:   args.timestamp,
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
			BlockHash:          args.blockHash,
			BlockRound:         args.blockRound,
			IsFinalized:        false,
			ShardID:            args.selfShardID,
			EventOrder:         args.eventOrder,
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
			BlockHash:   args.blockHash,
			BlockRound:  args.blockRound,
			IsFinalized: false,
			ShardID:     args.selfShardID,
			EventOrder:  args.eventOrder,
			GlobalPause: bytesToBool(topics[1]),
			Timestamp:   args.timestamp,
			TimestampMs: args.timestampMs,
		}
	case drwaWhitePaperCidSetEvent:
		if len(topics) < 2 {
			return nil
		}

		return &data.DrwaTokenPolicyRecord{
			TxHash:        args.txHashHexEncoded,
			TokenID:       string(topics[0]),
			EventType:     identifier,
			BlockHash:     args.blockHash,
			BlockRound:    args.blockRound,
			IsFinalized:   false,
			ShardID:       args.selfShardID,
			EventOrder:    args.eventOrder,
			WhitePaperCID: string(topics[1]),
			Timestamp:     args.timestamp,
			TimestampMs:   args.timestampMs,
		}
	case drwaRegistrationStatusSetEvent:
		if len(topics) < 2 {
			return nil
		}

		return &data.DrwaTokenPolicyRecord{
			TxHash:             args.txHashHexEncoded,
			TokenID:            string(topics[0]),
			EventType:          identifier,
			BlockHash:          args.blockHash,
			BlockRound:         args.blockRound,
			IsFinalized:        false,
			ShardID:            args.selfShardID,
			EventOrder:         args.eventOrder,
			RegistrationStatus: string(topics[1]),
			Timestamp:          args.timestamp,
			TimestampMs:        args.timestampMs,
		}
	case drwaWindDownInitiatedEvent:
		if len(topics) < 1 {
			return nil
		}

		return &data.DrwaTokenPolicyRecord{
			TxHash:            args.txHashHexEncoded,
			TokenID:           string(topics[0]),
			EventType:         identifier,
			BlockHash:         args.blockHash,
			BlockRound:        args.blockRound,
			IsFinalized:       false,
			ShardID:           args.selfShardID,
			EventOrder:        args.eventOrder,
			WindDownInitiated: true,
			Timestamp:         args.timestamp,
			TimestampMs:       args.timestampMs,
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
		DenialCode:  normalizeDRWADenialCode(topics[1]),
		BlockHash:   args.blockHash,
		BlockRound:  args.blockRound,
		IsFinalized: false,
		ShardID:     args.selfShardID,
		EventOrder:  args.eventOrder,
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
		BlockHash:   args.blockHash,
		BlockRound:  args.blockRound,
		IsFinalized: false,
		ShardID:     args.selfShardID,
		EventOrder:  args.eventOrder,
		Timestamp:   args.timestamp,
		TimestampMs: args.timestampMs,
	}
	if len(topics) >= 3 {
		record.HolderPolicyVersion = big.NewInt(0).SetBytes(topics[2]).Uint64()
	}
	if len(topics) >= 4 {
		record.KYCStatus = validateComplianceStatus(topics[3])
	}
	if len(topics) >= 5 {
		record.AMLStatus = validateComplianceStatus(topics[4])
	}
	if len(topics) >= 6 {
		record.InvestorClass = validateFieldLength(topics[5], 64)
	}
	if len(topics) >= 7 {
		record.JurisdictionCode = validateJurisdictionCode(topics[6])
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
	if identifier != drwaAuditorAcceptedEvent &&
		identifier != drwaAuditorProposedEvent &&
		identifier != drwaAuditorRevokedEvent &&
		identifier != drwaAttestationRecordedEvent &&
		identifier != drwaAttestationOverwrittenEvent {
		return nil
	}

	topics := args.event.GetTopics()
	if len(topics) < 1 {
		return nil
	}

	record := &data.DrwaAttestationRecord{
		TxHash:      args.txHashHexEncoded,
		EventType:   identifier,
		BlockHash:   args.blockHash,
		BlockRound:  args.blockRound,
		IsFinalized: false,
		ShardID:     args.selfShardID,
		EventOrder:  args.eventOrder,
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
		record.AttestationType = string(topics[3])
		record.Approved = bytesToBool(topics[4])
		record.AttestedRound = big.NewInt(0).SetBytes(topics[5]).Uint64()
		return record
	}

	if identifier == drwaAttestationOverwrittenEvent {
		if len(topics) < 3 {
			return nil
		}

		record.TokenID = string(topics[0])
		record.Subject = string(topics[1])
		record.Auditor = string(topics[2])
		return record
	}

	record.Auditor = string(topics[0])
	return record
}

func (dep *drwaEventsProcessor) tryBuildControlEventRecord(identifier string, args *argsProcessEvent) *data.DrwaControlEventRecord {
	switch identifier {
	case drwaTransferAllowedEvent, drwaMetadataProtectionEvent, drwaGovernanceProposedEvent, drwaGovernanceAcceptedEvent, drwaGovernanceRevokedEvent:
	default:
		return nil
	}

	topics := args.event.GetTopics()
	record := &data.DrwaControlEventRecord{
		TxHash:      args.txHashHexEncoded,
		EventType:   identifier,
		Topics:      encodeTopics(topics),
		BlockHash:   args.blockHash,
		BlockRound:  args.blockRound,
		IsFinalized: false,
		ShardID:     args.selfShardID,
		EventOrder:  args.eventOrder,
		Timestamp:   args.timestamp,
		TimestampMs: args.timestampMs,
	}

	// The checked-in DRWA event schema explicitly documents governance topic[0]
	// as the proposed / accepted governance address.
	if (identifier == drwaGovernanceProposedEvent || identifier == drwaGovernanceAcceptedEvent || identifier == drwaGovernanceRevokedEvent) && len(topics) >= 1 {
		record.Governance = string(topics[0])
	}

	return record
}

func encodeTopics(topics [][]byte) []string {
	if len(topics) == 0 {
		return nil
	}

	encoded := make([]string, 0, len(topics))
	for _, topic := range topics {
		encoded = append(encoded, hex.EncodeToString(topic))
	}

	return encoded
}

func normalizeDRWADenialCode(raw []byte) string {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return ""
	}

	if canonical, ok := drwaCanonicalDenialCodes[trimmed]; ok {
		return canonical
	}

	upper := strings.ToUpper(trimmed)
	if canonical, ok := drwaCanonicalDenialCodes[upper]; ok {
		return canonical
	}

	// Preserve unrecognized values verbatim (after trimming) rather than
	// dropping evidence, but canonicalize all known denial identifiers to the
	// shared mx-chain-core-go representation.
	return trimmed
}

var allowedComplianceStatuses = map[string]struct{}{
	"approved": {}, "pending": {}, "rejected": {}, "expired": {}, "": {},
}

func validateComplianceStatus(raw []byte) string {
	v := strings.TrimSpace(string(raw))
	if _, ok := allowedComplianceStatuses[strings.ToLower(v)]; ok {
		return v
	}
	return ""
}

func validateJurisdictionCode(raw []byte) string {
	v := strings.TrimSpace(string(raw))
	if v == "" {
		return v
	}
	if len(v) == 2 {
		upper := strings.ToUpper(v)
		allAlpha := true
		for _, c := range upper {
			if c < 'A' || c > 'Z' {
				allAlpha = false
				break
			}
		}
		if allAlpha {
			return upper
		}
	}
	return ""
}

func validateFieldLength(raw []byte, maxLen int) string {
	v := strings.TrimSpace(string(raw))
	if len(v) > maxLen {
		return v[:maxLen]
	}
	return v
}
