package logsevents

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/multiversx/mx-chain-es-indexer-go/data"
	"github.com/multiversx/mx-chain-es-indexer-go/process/elasticproc/converters"
)

const maxDRWADocumentIDLength = 400

// SerializeDRWADenials writes denial records to the drwa-denials Elasticsearch index.
func (lep *logsAndEventsProcessor) SerializeDRWADenials(records []*data.DrwaDenialRecord, buffSlice *data.BufferSlice, index string) error {
	for _, record := range records {
		meta, serialized, err := prepareDRWARecord(
			fmt.Sprintf("%s-denial-%s-%d", record.TxHash, record.DenialCode, record.EventOrder),
			index,
			record,
		)
		if err != nil {
			return err
		}
		if err = buffSlice.PutData(meta, serialized); err != nil {
			return err
		}
	}
	return nil
}

// SerializeDRWAIdentities writes identity lifecycle records to the drwa-identities index.
func (lep *logsAndEventsProcessor) SerializeDRWAIdentities(records []*data.DrwaIdentityRecord, buffSlice *data.BufferSlice, index string) error {
	for _, record := range records {
		meta, serialized, err := prepareDRWARecord(
			fmt.Sprintf("%s-%s-%s-%d", record.TxHash, record.Subject, record.EventType, record.EventOrder),
			index,
			record,
		)
		if err != nil {
			return err
		}
		if err = buffSlice.PutData(meta, serialized); err != nil {
			return err
		}
	}
	return nil
}

// SerializeDRWAHolderCompliance writes holder compliance records to the drwa-holder-compliance index.
func (lep *logsAndEventsProcessor) SerializeDRWAHolderCompliance(records []*data.DrwaHolderComplianceRecord, buffSlice *data.BufferSlice, index string) error {
	for _, record := range records {
		meta, serialized, err := prepareDRWARecord(
			fmt.Sprintf("%s-%s-%s-%d", record.TxHash, record.TokenID, record.Holder, record.EventOrder),
			index,
			record,
		)
		if err != nil {
			return err
		}
		if err = buffSlice.PutData(meta, serialized); err != nil {
			return err
		}
	}
	return nil
}

// SerializeDRWAAttestations writes auditor attestation records to the drwa-attestations index.
func (lep *logsAndEventsProcessor) SerializeDRWAAttestations(records []*data.DrwaAttestationRecord, buffSlice *data.BufferSlice, index string) error {
	for _, record := range records {
		meta, serialized, err := prepareDRWARecord(
			fmt.Sprintf("%s-%s-%s-%d", record.TxHash, record.EventType, record.Auditor, record.EventOrder),
			index,
			record,
		)
		if err != nil {
			return err
		}
		if err = buffSlice.PutData(meta, serialized); err != nil {
			return err
		}
	}
	return nil
}

// SerializeDRWATokenPolicies writes policy history records to the drwa-token-policies index.
func (lep *logsAndEventsProcessor) SerializeDRWATokenPolicies(records []*data.DrwaTokenPolicyRecord, buffSlice *data.BufferSlice, index string) error {
	for _, record := range records {
		meta, serialized, err := prepareDRWARecord(
			fmt.Sprintf("%s-%s-%s-%d", record.TxHash, record.TokenID, record.EventType, record.EventOrder),
			index,
			record,
		)
		if err != nil {
			return err
		}
		if err = buffSlice.PutData(meta, serialized); err != nil {
			return err
		}
	}
	return nil
}

// SerializeDRWAControlEvents writes generic DRWA control-plane events to the
// dedicated control-event index.
func (lep *logsAndEventsProcessor) SerializeDRWAControlEvents(records []*data.DrwaControlEventRecord, buffSlice *data.BufferSlice, index string) error {
	for _, record := range records {
		meta, serialized, err := prepareDRWARecord(
			fmt.Sprintf("%s-%s-%d", record.TxHash, record.EventType, record.EventOrder),
			index,
			record,
		)
		if err != nil {
			return err
		}
		if err = buffSlice.PutData(meta, serialized); err != nil {
			return err
		}
	}

	return nil
}

func prepareDRWARecord(id string, index string, record any) ([]byte, []byte, error) {
	return prepareRecordWithLabel(id, index, record, "DRWA")
}

func prepareRecordWithLabel(id string, index string, record any, label string) ([]byte, []byte, error) {
	if len(id) > maxDRWADocumentIDLength {
		return nil, nil, errors.New(label + " document id exceeds maximum length")
	}

	serialized, err := json.Marshal(record)
	if err != nil {
		return nil, nil, err
	}

	meta := []byte(fmt.Sprintf(`{ "index" : { "_index": "%s", "_id" : "%s" } }%s`, index, converters.JsonEscape(id), "\n"))
	return meta, serialized, nil
}
