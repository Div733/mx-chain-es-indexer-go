package logsevents

import (
	"encoding/binary"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-es-indexer-go/data"
	"github.com/stretchr/testify/require"
)

func newTestMRVEventsProcessorAllowAll() *mrvEventsProcessor {
	return &mrvEventsProcessor{
		authorizedEmitters: map[string]struct{}{"": struct{}{}},
	}
}

func TestMRVEventsProcessorBuildsAnchoredProofRecord(t *testing.T) {
	t.Parallel()

	tx := &data.Transaction{}
	hash := "hash"
	proc := newTestMRVEventsProcessorAllowAll()

	res := proc.processEvent(&argsProcessEvent{
		event: &transaction.Event{
			Identifier: []byte(mrvReportAnchoredV2Event),
			Topics: [][]byte{
				[]byte("report-1"),
				[]byte("tenant-1"),
				[]byte("farm-1"),
				[]byte("season-1"),
			},
			AdditionalData: [][]byte{
				[]byte("sha256:report"),
				[]byte("sha256"),
				[]byte("json-c14n-v1"),
				mrvUint64Bytes(7),
				mrvUint64Bytes(42),
				[]byte("project-1"),
				[]byte("sha256:evidence"),
			},
		},
		txs: map[string]*data.Transaction{
			hash: tx,
		},
		txHashHexEncoded: hash,
		blockHash:        "block-hash",
		blockRound:       88,
		selfShardID:      2,
		eventOrder:       5,
		timestamp:        1000,
		timestampMs:      1000000,
	})

	require.True(t, res.processed)
	require.True(t, tx.HasOperations)
	require.Equal(t, "mrv", tx.Operation)
	require.Equal(t, mrvReportAnchoredV2Event, tx.Function)
	require.NotNil(t, res.mrvAnchoredProof)
	require.Equal(t, "report-1", res.mrvAnchoredProof.ReportID)
	require.Equal(t, "tenant-1", res.mrvAnchoredProof.PublicTenantID)
	require.Equal(t, "farm-1", res.mrvAnchoredProof.PublicFarmID)
	require.Equal(t, "season-1", res.mrvAnchoredProof.PublicSeasonID)
	require.Equal(t, "project-1", res.mrvAnchoredProof.PublicProjectID)
	require.Equal(t, "sha256:report", res.mrvAnchoredProof.ReportHash)
	require.Equal(t, uint64(7), res.mrvAnchoredProof.MethodologyVersion)
	require.Equal(t, uint64(42), res.mrvAnchoredProof.AnchoredAt)
	require.Equal(t, "sha256:evidence", res.mrvAnchoredProof.EvidenceManifestHash)
	require.Equal(t, "block-hash", res.mrvAnchoredProof.BlockHash)
	require.Equal(t, uint64(88), res.mrvAnchoredProof.BlockRound)
	require.False(t, res.mrvAnchoredProof.IsFinalized)
	require.Equal(t, uint32(2), res.mrvAnchoredProof.ShardID)
	require.Equal(t, 5, res.mrvAnchoredProof.EventOrder)
}

func TestMRVEventsProcessorRejectsUnauthorizedEmitter(t *testing.T) {
	t.Parallel()

	proc := newMRVEventsProcessorWithAuthorizedEmitters([][]byte{[]byte("allowed-emitter")})
	res := proc.processEvent(&argsProcessEvent{
		event:            mrvAnchoredEvent(),
		logAddress:       []byte("other-emitter"),
		txs:              map[string]*data.Transaction{},
		txHashHexEncoded: "hash",
	})

	require.False(t, res.processed)
	require.Nil(t, res.mrvAnchoredProof)
}

func TestMRVEventsProcessorWithExplicitEmptyEmitterListFailsClosed(t *testing.T) {
	t.Parallel()

	proc := newMRVEventsProcessorWithAuthorizedEmitters(nil)
	res := proc.processEvent(&argsProcessEvent{
		event:            mrvAnchoredEvent(),
		logAddress:       []byte("any-emitter"),
		txs:              map[string]*data.Transaction{},
		txHashHexEncoded: "hash",
	})

	require.False(t, res.processed)
	require.Nil(t, res.mrvAnchoredProof)
}

func TestMRVEventsProcessorAcceptsAuthorizedEmitter(t *testing.T) {
	t.Parallel()

	proc := newMRVEventsProcessorWithAuthorizedEmitters([][]byte{[]byte("allowed-emitter")})
	res := proc.processEvent(&argsProcessEvent{
		event:            mrvAnchoredEvent(),
		logAddress:       []byte("allowed-emitter"),
		txs:              map[string]*data.Transaction{},
		txHashHexEncoded: "hash",
	})

	require.True(t, res.processed)
	require.NotNil(t, res.mrvAnchoredProof)
}

func TestMRVEventsProcessorRejectsPartialCanonicalPayload(t *testing.T) {
	t.Parallel()

	proc := newTestMRVEventsProcessorAllowAll()
	res := proc.processEvent(&argsProcessEvent{
		event: &transaction.Event{
			Identifier: []byte(mrvReportAnchoredV2Event),
			Topics:     [][]byte{[]byte("report-1")},
		},
		txs:              map[string]*data.Transaction{},
		txHashHexEncoded: "hash",
	})

	require.True(t, res.processed)
	require.Nil(t, res.mrvAnchoredProof)
}

func TestMRVEventsProcessorRejectsNonV2CanonicalPayloadShape(t *testing.T) {
	t.Parallel()

	proc := newTestMRVEventsProcessorAllowAll()
	event := mrvAnchoredEvent()
	event.Topics = append(event.Topics, []byte("unexpected-topic"))

	res := proc.processEvent(&argsProcessEvent{
		event:            event,
		txs:              map[string]*data.Transaction{},
		txHashHexEncoded: "hash-extra-topic",
	})

	require.True(t, res.processed)
	require.Nil(t, res.mrvAnchoredProof)

	event = mrvAnchoredEvent()
	event.AdditionalData = append(event.AdditionalData, []byte("unexpected-data"))

	res = proc.processEvent(&argsProcessEvent{
		event:            event,
		txs:              map[string]*data.Transaction{},
		txHashHexEncoded: "hash-extra-data",
	})

	require.True(t, res.processed)
	require.Nil(t, res.mrvAnchoredProof)
}

func TestMRVEventsProcessorRejectsNonCanonicalTextFields(t *testing.T) {
	t.Parallel()

	proc := newTestMRVEventsProcessorAllowAll()
	event := mrvAnchoredEvent()
	event.Topics[0] = []byte("report with spaces")

	res := proc.processEvent(&argsProcessEvent{
		event:            event,
		txs:              map[string]*data.Transaction{},
		txHashHexEncoded: "hash",
	})

	require.True(t, res.processed)
	require.Nil(t, res.mrvAnchoredProof)
}

func mrvAnchoredEvent() *transaction.Event {
	return &transaction.Event{
		Identifier: []byte(mrvReportAnchoredV2Event),
		Topics: [][]byte{
			[]byte("report-1"),
			[]byte("tenant-1"),
			[]byte("farm-1"),
			[]byte("season-1"),
		},
		AdditionalData: [][]byte{
			[]byte("sha256:report"),
			[]byte("sha256"),
			[]byte("json-c14n-v1"),
			mrvUint64Bytes(7),
			mrvUint64Bytes(42),
			[]byte("project-1"),
			[]byte("sha256:evidence"),
		},
	}
}

func mrvUint64Bytes(value uint64) []byte {
	result := make([]byte, 8)
	binary.BigEndian.PutUint64(result, value)
	return result
}
