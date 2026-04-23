package elasticproc

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/multiversx/mx-chain-es-indexer-go/core/request"
	elasticIndexer "github.com/multiversx/mx-chain-es-indexer-go/process/dataindexer"
	logger "github.com/multiversx/mx-chain-logger-go"
)

var reconcilerLog = logger.GetOrCreate("indexer/drwa-reconciler")

// drwaExpectedFinalitySeconds is the maximum time a DRWA record should remain
// unfinalized before the reconciler treats the FinalizedBlock message as lost.
// MultiversX finalises blocks in ~2 rounds (~6 s); 5 minutes is a very
// conservative safety margin.
const drwaExpectedFinalitySeconds = 300

// drwaReconciler periodically scans all six DRWA compliance indices for records
// that have been in isFinalized=false state longer than drwaExpectedFinalitySeconds
// and marks them finalized.  This is the safety net for dropped FinalizedBlock
// WebSocket messages.
type drwaReconciler struct {
	elasticClient    DatabaseClientHandler
	statusMetrics    reconcilerMetrics
	interval         time.Duration
	staleThreshold   time.Duration
	quit             chan struct{}
	once             sync.Once
}

type reconcilerMetrics interface {
	IncrementDRWAStaleUnfinalizedCount()
}

func newDRWAReconciler(elasticClient DatabaseClientHandler, statusMetrics reconcilerMetrics, interval time.Duration) *drwaReconciler {
	return &drwaReconciler{
		elasticClient:  elasticClient,
		statusMetrics:  statusMetrics,
		interval:       interval,
		staleThreshold: drwaExpectedFinalitySeconds * time.Second,
		quit:           make(chan struct{}),
	}
}

// start launches the background reconciliation loop.
func (r *drwaReconciler) start() {
	r.once.Do(func() {
		go r.loop()
	})
}

// stop signals the reconciliation loop to exit.
func (r *drwaReconciler) stop() {
	r.once.Do(func() {})
	select {
	case <-r.quit:
	default:
		close(r.quit)
	}
}

func (r *drwaReconciler) loop() {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.reconcile()
		case <-r.quit:
			return
		}
	}
}

func (r *drwaReconciler) reconcile() {
	cutoff := time.Now().Add(-r.staleThreshold).Unix()

	query, err := buildStaleUnfinalizedQuery(cutoff)
	if err != nil {
		reconcilerLog.Warn("drwaReconciler.reconcile: failed to build query", "error", err)
		return
	}

	staleFound := false
	for _, index := range []string{
		elasticIndexer.DrwaDenialsIndex,
		elasticIndexer.DrwaIdentitiesIndex,
		elasticIndexer.DrwaHolderComplianceIndex,
		elasticIndexer.DrwaAttestationsIndex,
		elasticIndexer.DrwaTokenPoliciesIndex,
		elasticIndexer.DrwaControlEventsIndex,
	} {
		count, err := r.elasticClient.DoCountRequest(
			context.WithValue(context.Background(), request.ContextKey, request.ExtendTopicWithShardID(request.GetTopic, 0)),
			index,
			query,
		)
		if err != nil {
			reconcilerLog.Warn("drwaReconciler: count failed", "index", index, "error", err)
			continue
		}
		if count == 0 {
			continue
		}

		staleFound = true
		reconcilerLog.Warn("drwaReconciler: stale unfinalized DRWA records detected — marking finalized",
			"index", index, "count", count)

		updateQuery, err := buildMarkFinalizedQuery(cutoff)
		if err != nil {
			reconcilerLog.Warn("drwaReconciler: failed to build update query", "error", err)
			continue
		}

		ctx := context.WithValue(context.Background(), request.ContextKey, request.ExtendTopicWithShardID(request.UpdateTopic, 0))
		if err := r.elasticClient.UpdateByQuery(ctx, index, bytes.NewBuffer(updateQuery)); err != nil {
			reconcilerLog.Warn("drwaReconciler: UpdateByQuery failed", "index", index, "error", err)
		}
	}

	if staleFound {
		r.statusMetrics.IncrementDRWAStaleUnfinalizedCount()
	}
}

// buildStaleUnfinalizedQuery returns the raw JSON body for counting records
// that are unfinalized and older than cutoff (Unix timestamp).
func buildStaleUnfinalizedQuery(cutoffUnix int64) ([]byte, error) {
	q := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": []interface{}{
					map[string]interface{}{"term": map[string]interface{}{"isFinalized": false}},
					map[string]interface{}{"range": map[string]interface{}{
						"timestamp": map[string]interface{}{"lt": cutoffUnix},
					}},
				},
			},
		},
	}
	return json.Marshal(q)
}

// buildMarkFinalizedQuery returns the raw JSON body for an update_by_query that
// sets isFinalized=true on all stale unfinalized records.
func buildMarkFinalizedQuery(cutoffUnix int64) ([]byte, error) {
	q := map[string]interface{}{
		"script": map[string]interface{}{
			"source": "ctx._source.isFinalized = true",
			"lang":   "painless",
		},
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": []interface{}{
					map[string]interface{}{"term": map[string]interface{}{"isFinalized": false}},
					map[string]interface{}{"range": map[string]interface{}{
						"timestamp": map[string]interface{}{"lt": cutoffUnix},
					}},
				},
			},
		},
	}
	return json.Marshal(q)
}
