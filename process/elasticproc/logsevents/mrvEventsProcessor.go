package logsevents

import (
	"encoding/binary"
	"strings"
	"unicode/utf8"

	"github.com/multiversx/mx-chain-es-indexer-go/data"
)

const (
	mrvReportAnchoredV2Event = "mrvReportAnchoredV2"
	mrvReportAmendedV2Event  = "mrvReportAmendedV2"

	mrvReportV2TopicCount          = 4
	mrvReportV2AdditionalDataCount = 7
)

var mrvCanonicalEventsMap = map[string]struct{}{
	strings.ToLower(mrvReportAnchoredV2Event): {},
	strings.ToLower(mrvReportAmendedV2Event):  {},
}

type mrvEventsProcessor struct {
	authorizedEmitters map[string]struct{}
}

type mrvAdditionalDataHandler interface {
	GetAdditionalData() [][]byte
}

func newMRVEventsProcessor() *mrvEventsProcessor {
	return newMRVEventsProcessorWithAuthorizedEmitters(nil)
}

func newMRVEventsProcessorWithAuthorizedEmitters(emitters [][]byte) *mrvEventsProcessor {
	processor := &mrvEventsProcessor{
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

func (dep *mrvEventsProcessor) processEvent(args *argsProcessEvent) argOutputProcessEvent {
	if !dep.isAuthorizedEmitter(args.logAddress) {
		return argOutputProcessEvent{}
	}

	identifier := string(args.event.GetIdentifier())
	if _, ok := mrvCanonicalEventsMap[strings.ToLower(identifier)]; !ok {
		return argOutputProcessEvent{}
	}

	record := dep.tryBuildAnchoredProofRecord(identifier, args)

	tx, ok := args.txs[args.txHashHexEncoded]
	if ok {
		tx.HasOperations = true
		tx.Operation = "mrv"
		tx.Function = identifier
		return argOutputProcessEvent{
			processed:        true,
			mrvAnchoredProof: record,
		}
	}

	scr, ok := args.scrs[args.txHashHexEncoded]
	if ok {
		scr.HasOperations = true
		scr.Operation = "mrv"
		scr.Function = identifier
		return argOutputProcessEvent{
			processed:        true,
			mrvAnchoredProof: record,
		}
	}

	return argOutputProcessEvent{
		processed:        true,
		mrvAnchoredProof: record,
	}
}

func (dep *mrvEventsProcessor) isAuthorizedEmitter(logAddress []byte) bool {
	if len(dep.authorizedEmitters) == 0 {
		return false
	}

	_, ok := dep.authorizedEmitters[string(logAddress)]
	return ok
}

func (dep *mrvEventsProcessor) tryBuildAnchoredProofRecord(identifier string, args *argsProcessEvent) *data.MrvAnchoredProofRecord {
	topics := args.event.GetTopics()
	additionalData := getMRVAdditionalData(args)
	if len(topics) != mrvReportV2TopicCount || len(additionalData) != mrvReportV2AdditionalDataCount {
		return nil
	}
	if !isCanonicalMRVFields(topics, additionalData) {
		return nil
	}

	return &data.MrvAnchoredProofRecord{
		TxHash:               args.txHashHexEncoded,
		EventType:            identifier,
		ReportID:             string(topics[0]),
		PublicTenantID:       string(topics[1]),
		PublicFarmID:         string(topics[2]),
		PublicSeasonID:       string(topics[3]),
		ReportHash:           string(additionalData[0]),
		HashAlgo:             string(additionalData[1]),
		Canonicalization:     string(additionalData[2]),
		MethodologyVersion:   mrvBytesToUint64(additionalData[3]),
		AnchoredAt:           mrvBytesToUint64(additionalData[4]),
		PublicProjectID:      string(additionalData[5]),
		EvidenceManifestHash: string(additionalData[6]),
		BlockHash:            args.blockHash,
		BlockRound:           args.blockRound,
		IsFinalized:          false,
		ShardID:              args.selfShardID,
		EventOrder:           args.eventOrder,
		Timestamp:            args.timestamp,
		TimestampMs:          args.timestampMs,
	}
}

func isCanonicalMRVFields(topics [][]byte, additionalData [][]byte) bool {
	for _, field := range topics {
		if !isCanonicalMRVText(field, 256) {
			return false
		}
	}

	for idx, field := range additionalData {
		if idx == 3 || idx == 4 {
			continue
		}
		if !isCanonicalMRVText(field, 512) {
			return false
		}
	}

	return true
}

func isCanonicalMRVText(field []byte, maxLen int) bool {
	if len(field) == 0 || len(field) > maxLen || !utf8.Valid(field) {
		return false
	}
	for _, r := range string(field) {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			continue
		}
		switch r {
		case '.', '_', ':', '-':
			continue
		default:
			return false
		}
	}

	return true
}

func getMRVAdditionalData(args *argsProcessEvent) [][]byte {
	eventWithAdditionalData, ok := args.event.(mrvAdditionalDataHandler)
	if !ok {
		return nil
	}

	return eventWithAdditionalData.GetAdditionalData()
}

func mrvBytesToUint64(raw []byte) uint64 {
	if len(raw) == 0 {
		return 0
	}
	if len(raw) <= 8 {
		padded := make([]byte, 8)
		copy(padded[8-len(raw):], raw)
		return binary.BigEndian.Uint64(padded)
	}

	var value uint64
	for _, b := range raw {
		if b < '0' || b > '9' {
			return 0
		}
		value = value*10 + uint64(b-'0')
	}

	return value
}
