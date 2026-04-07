package logsevents

import (
	"encoding/json"
	"fmt"

	"github.com/multiversx/mx-chain-es-indexer-go/data"
	"github.com/multiversx/mx-chain-es-indexer-go/process/elasticproc/converters"
)

// SerializeDRWADenials writes denial records to the drwa-denials Elasticsearch index.
func (lep *logsAndEventsProcessor) SerializeDRWADenials(records []*data.DrwaDenialRecord, buffSlice *data.BufferSlice, index string) error {
	for _, record := range records {
		meta, serialized, err := prepareDRWARecord(record.TxHash+"-denial-"+record.DenialCode, index, record)
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
		meta, serialized, err := prepareDRWARecord(record.TxHash+"-"+record.TokenID+"-"+record.Holder, index, record)
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
		meta, serialized, err := prepareDRWARecord(record.TxHash+"-"+record.EventType+"-"+record.Auditor, index, record)
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
		meta, serialized, err := prepareDRWARecord(record.TxHash+"-"+record.TokenID+"-"+record.EventType, index, record)
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
	serialized, err := json.Marshal(record)
	if err != nil {
		return nil, nil, err
	}

	meta := []byte(fmt.Sprintf(`{ "index" : { "_index": "%s", "_id" : "%s" } }%s`, index, converters.JsonEscape(id), "\n"))
	return meta, serialized, nil
}
