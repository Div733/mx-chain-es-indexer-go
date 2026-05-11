package logsevents

import (
	"fmt"

	"github.com/multiversx/mx-chain-es-indexer-go/data"
)

// SerializeMRVAnchoredProofs writes report proof records to the mrv-anchored-proofs index.
func (lep *logsAndEventsProcessor) SerializeMRVAnchoredProofs(records []*data.MrvAnchoredProofRecord, buffSlice *data.BufferSlice, index string) error {
	for _, record := range records {
		meta, serialized, err := prepareRecordWithLabel(
			fmt.Sprintf("%s-%s-%s-%d", record.TxHash, record.ReportID, record.EventType, record.EventOrder),
			index,
			record,
			"MRV",
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
