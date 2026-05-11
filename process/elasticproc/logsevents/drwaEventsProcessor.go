package logsevents

import (
	"encoding/hex"
	"math/big"
	"strings"

	coredrwa "github.com/multiversx/mx-chain-core-go/data/drwa"
	"github.com/multiversx/mx-chain-es-indexer-go/data"
)

const (
	drwaAssetRegisteredEvent         = "drwaAssetRegistered"
	drwaAssetUpdatedEvent            = "drwaAssetUpdated"
	drwaTokenPolicyEvent             = "drwaTokenPolicy"
	drwaHolderComplianceEvent        = "drwaHolderCompliance"
	drwaTransferDeniedEvent          = "drwaTransferDenied"
	drwaTransferAllowedEvent         = "drwaTransferAllowed"
	drwaGlobalPauseEvent             = "drwaGlobalPause"
	drwaMetadataProtectionEvent      = "drwaMetadataProtection"
	drwaWhitePaperCidSetEvent        = "drwaWhitePaperCidSet"
	drwaRegistrationStatusSetEvent   = "drwaRegistrationStatusSet"
	drwaIdentityRegisteredEvent      = "drwaIdentityRegistered"
	drwaComplianceUpdatedEvent       = "drwaComplianceUpdated"
	drwaIdentityDeactivatedEvent     = "drwaIdentityDeactivated"
	drwaIdentityErasedEvent          = "drwaIdentityErased"
	drwaWindDownInitiatedEvent       = "drwaWindDownInitiated"
	drwaAuditorProposedEvent         = "drwaAuditorProposed"
	drwaAuditorAcceptedEvent         = "drwaAuditorAccepted"
	drwaAuditorRevokedEvent          = "drwaAuditorRevoked"
	drwaAttestationOverwrittenEvent  = "drwaAttestationOverwritten"
	drwaAttestationRecordedEvent     = "drwaAttestationRecorded"
	drwaGovernanceProposedEvent      = "drwaGovernanceProposed"
	drwaGovernanceAcceptedEvent      = "drwaGovernanceAccepted"
	drwaGovernanceRevokedEvent       = "drwaGovernanceRevoked"
	drwaAuthActionProposedEvent      = "drwaAuthActionProposed"
	drwaAuthActionSignedEvent        = "drwaAuthActionSigned"
	drwaAuthActionUnsignedEvent      = "drwaAuthActionUnsigned"
	drwaAuthActionDiscardedEvent     = "drwaAuthActionDiscarded"
	drwaAuthActionPerformedEvent     = "drwaAuthActionPerformed"
	drwaAuthorizedCallerUpdatedEvent = "drwaAuthorizedCallerUpdated"
	drwaSignerAddedEvent             = "drwaSignerAdded"
	drwaSignerRemovedEvent           = "drwaSignerRemoved"
	drwaSignerReplacedEvent          = "drwaSignerReplaced"
	drwaQuorumChangedEvent           = "drwaQuorumChanged"
)

// drwaCanonicalEventsMap is the exact allow-list of DRWA event identifiers
// (lowercased).  Only events in this map are processed — prefix matching is
// intentionally avoided so that arbitrary contracts cannot pollute the
// compliance index by emitting events whose identifier starts with "drwa".
var drwaCanonicalEventsMap map[string]string
var drwaCanonicalDenialCodes map[string]string
var drwaCanonicalKYCStatuses map[string]struct{}
var drwaCanonicalAMLStatuses map[string]struct{}
var drwaCanonicalRegistrationStatuses map[string]struct{}

func init() {
	drwaCanonicalEventsMap = map[string]string{
		strings.ToLower(drwaAssetRegisteredEvent):         drwaAssetRegisteredEvent,
		strings.ToLower(drwaAssetUpdatedEvent):            drwaAssetUpdatedEvent,
		strings.ToLower(drwaTokenPolicyEvent):             drwaTokenPolicyEvent,
		strings.ToLower(drwaHolderComplianceEvent):        drwaHolderComplianceEvent,
		strings.ToLower(drwaTransferDeniedEvent):          drwaTransferDeniedEvent,
		strings.ToLower(drwaTransferAllowedEvent):         drwaTransferAllowedEvent,
		strings.ToLower(drwaGlobalPauseEvent):             drwaGlobalPauseEvent,
		strings.ToLower(drwaMetadataProtectionEvent):      drwaMetadataProtectionEvent,
		strings.ToLower(drwaWhitePaperCidSetEvent):        drwaWhitePaperCidSetEvent,
		strings.ToLower(drwaRegistrationStatusSetEvent):   drwaRegistrationStatusSetEvent,
		strings.ToLower(drwaIdentityRegisteredEvent):      drwaIdentityRegisteredEvent,
		strings.ToLower(drwaComplianceUpdatedEvent):       drwaComplianceUpdatedEvent,
		strings.ToLower(drwaIdentityDeactivatedEvent):     drwaIdentityDeactivatedEvent,
		strings.ToLower(drwaIdentityErasedEvent):          drwaIdentityErasedEvent,
		strings.ToLower(drwaWindDownInitiatedEvent):       drwaWindDownInitiatedEvent,
		strings.ToLower(drwaAuditorProposedEvent):         drwaAuditorProposedEvent,
		strings.ToLower(drwaAuditorAcceptedEvent):         drwaAuditorAcceptedEvent,
		strings.ToLower(drwaAuditorRevokedEvent):          drwaAuditorRevokedEvent,
		strings.ToLower(drwaAttestationOverwrittenEvent):  drwaAttestationOverwrittenEvent,
		strings.ToLower(drwaAttestationRecordedEvent):     drwaAttestationRecordedEvent,
		strings.ToLower(drwaGovernanceProposedEvent):      drwaGovernanceProposedEvent,
		strings.ToLower(drwaGovernanceAcceptedEvent):      drwaGovernanceAcceptedEvent,
		strings.ToLower(drwaGovernanceRevokedEvent):       drwaGovernanceRevokedEvent,
		strings.ToLower(drwaAuthActionProposedEvent):      drwaAuthActionProposedEvent,
		strings.ToLower(drwaAuthActionSignedEvent):        drwaAuthActionSignedEvent,
		strings.ToLower(drwaAuthActionUnsignedEvent):      drwaAuthActionUnsignedEvent,
		strings.ToLower(drwaAuthActionDiscardedEvent):     drwaAuthActionDiscardedEvent,
		strings.ToLower(drwaAuthActionPerformedEvent):     drwaAuthActionPerformedEvent,
		strings.ToLower(drwaAuthorizedCallerUpdatedEvent): drwaAuthorizedCallerUpdatedEvent,
		strings.ToLower(drwaSignerAddedEvent):             drwaSignerAddedEvent,
		strings.ToLower(drwaSignerRemovedEvent):           drwaSignerRemovedEvent,
		strings.ToLower(drwaSignerReplacedEvent):          drwaSignerReplacedEvent,
		strings.ToLower(drwaQuorumChangedEvent):           drwaQuorumChangedEvent,
	}

	drwaCanonicalDenialCodes = buildDRWACanonicalDenialCodes()
	drwaCanonicalKYCStatuses = buildCanonicalSet(
		"approved",
		"pending",
		"rejected",
		"expired",
		"not_started",
		"deactivated",
	)
	drwaCanonicalAMLStatuses = buildCanonicalSet(
		"clear",
		"pending",
		"flagged",
		"review",
		"blocked",
		"not_started",
		"deactivated",
	)
	drwaCanonicalRegistrationStatuses = buildCanonicalSet(
		"draft",
		"submitted",
		"approved",
		"rejected",
		"withdrawn",
	)
}

func buildDRWACanonicalDenialCodes() map[string]string {
	codes := coredrwa.AllDenialCodes()
	canonicalCodes := make(map[string]string, len(codes)+1)
	for _, code := range codes {
		canonicalCodes[string(code)] = string(code)
	}
	canonicalCodes[string(coredrwa.DenialUnknown)] = string(coredrwa.DenialUnknown)

	return canonicalCodes
}

func buildCanonicalSet(values ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}

	return result
}

type drwaEventsProcessor struct {
	authorizedEmitters map[string]struct{}
}

func newDRWAEventsProcessor() *drwaEventsProcessor {
	return newDRWAEventsProcessorWithAuthorizedEmitters(nil)
}

func newDRWAEventsProcessorOpenMode() *drwaEventsProcessor {
	return &drwaEventsProcessor{
		authorizedEmitters: map[string]struct{}{"": {}},
	}
}

func newDRWAEventsProcessorWithAuthorizedEmitters(emitters [][]byte) *drwaEventsProcessor {
	processor := &drwaEventsProcessor{
		authorizedEmitters: make(map[string]struct{}, len(emitters)),
	}

	for _, emitter := range emitters {
		if len(emitter) == 0 {
			continue
		}
		processor.authorizedEmitters[string(emitter)] = struct{}{}
	}

	return processor
}

// IsInterfaceNil returns true if there is no value under the interface
func (dep *drwaEventsProcessor) IsInterfaceNil() bool {
	return dep == nil
}

func (dep *drwaEventsProcessor) processEvent(args *argsProcessEvent) argOutputProcessEvent {
	if !dep.isAuthorizedEmitter(args.logAddress) {
		return argOutputProcessEvent{}
	}

	identifier := string(args.event.GetIdentifier())
	canonicalIdentifier, ok := drwaCanonicalEventsMap[strings.ToLower(identifier)]
	if !ok {
		return argOutputProcessEvent{}
	}
	identifier = canonicalIdentifier

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

func (dep *drwaEventsProcessor) isAuthorizedEmitter(logAddress []byte) bool {
	if len(dep.authorizedEmitters) == 0 {
		return false
	}

	_, ok := dep.authorizedEmitters[string(logAddress)]
	if ok {
		return true
	}

	// sentinel: empty string key means open mode (allow all)
	_, ok = dep.authorizedEmitters[""]
	return ok
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
		if !isValidDRWAWhitePaperCID(topics[1]) {
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
		if !isCanonicalDRWARegistrationStatus(topics[1]) {
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
		record.JurisdictionCode = string(topics[1])
		record.EntityType = string(topics[2])
	case drwaComplianceUpdatedEvent:
		if len(topics) < 3 {
			return nil
		}
		if !isCanonicalDRWAKYCStatus(topics[1]) || !isCanonicalDRWAAMLStatus(topics[2]) {
			return nil
		}
		record.KYCStatus = string(topics[1])
		record.AMLStatus = string(topics[2])
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
		if !isValidDRWAWhitePaperCID(topics[1]) {
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
		if !isCanonicalDRWARegistrationStatus(topics[1]) {
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
		if !isCanonicalDRWAKYCStatus(topics[3]) {
			return nil
		}
		record.KYCStatus = string(topics[3])
	}
	if len(topics) >= 5 {
		if !isCanonicalDRWAAMLStatus(topics[4]) {
			return nil
		}
		record.AMLStatus = string(topics[4])
	}
	if len(topics) >= 6 {
		if !isValidDRWAPolicyKey(topics[5]) {
			return nil
		}
		record.InvestorClass = string(topics[5])
	}
	if len(topics) >= 7 {
		if !isValidDRWAPolicyKey(topics[6]) {
			return nil
		}
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
		auditorAuthorized := bytesToBool(topics[10])
		record.AuditorAuthorized = &auditorAuthorized
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
	case drwaTransferAllowedEvent,
		drwaMetadataProtectionEvent,
		drwaGovernanceProposedEvent,
		drwaGovernanceAcceptedEvent,
		drwaGovernanceRevokedEvent,
		drwaAuthActionProposedEvent,
		drwaAuthActionSignedEvent,
		drwaAuthActionUnsignedEvent,
		drwaAuthActionDiscardedEvent,
		drwaAuthActionPerformedEvent,
		drwaAuthorizedCallerUpdatedEvent,
		drwaSignerAddedEvent,
		drwaSignerRemovedEvent,
		drwaSignerReplacedEvent,
		drwaQuorumChangedEvent:
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

	return string(coredrwa.DenialUnknown)
}

func isCanonicalDRWAKYCStatus(raw []byte) bool {
	_, ok := drwaCanonicalKYCStatuses[string(raw)]
	return ok
}

func isCanonicalDRWAAMLStatus(raw []byte) bool {
	_, ok := drwaCanonicalAMLStatuses[string(raw)]
	return ok
}

func isCanonicalDRWARegistrationStatus(raw []byte) bool {
	_, ok := drwaCanonicalRegistrationStatuses[string(raw)]
	return ok
}

func isValidDRWAPolicyKey(raw []byte) bool {
	if len(raw) == 0 || len(raw) > 64 {
		return false
	}

	for _, b := range raw {
		if !(isASCIIAlphaNumeric(b) || b == '.' || b == '_' || b == '-') {
			return false
		}
	}

	return true
}

func isValidDRWAWhitePaperCID(raw []byte) bool {
	if len(raw) < 10 || len(raw) > 128 {
		return false
	}

	if !(strings.HasPrefix(string(raw), "Qm") || strings.HasPrefix(string(raw), "bafy")) {
		return false
	}

	for _, b := range raw {
		if !isASCIIAlphaNumeric(b) {
			return false
		}
	}

	return true
}

func isASCIIAlphaNumeric(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}
