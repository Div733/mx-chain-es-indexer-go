package metrics

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"unicode"

	"github.com/multiversx/mx-chain-es-indexer-go/core/request"
)

const (
	operationCount              = "operations_count"
	errorsCount                 = "errors_count"
	totalTime                   = "total_time"
	totalData                   = "total_data"
	requestsErrors              = "requests_errors"
	drwaStaleUnfinalizedTopic   = "drwa_stale_unfinalized_records"
)

type statusMetrics struct {
	metrics                    map[string]*request.MetricsResponse
	drwaStaleUnfinalizedCount  uint64
	mut                        sync.RWMutex
}

// NewStatusMetrics will return an instance of the statusMetrics
func NewStatusMetrics() *statusMetrics {
	return &statusMetrics{
		metrics: make(map[string]*request.MetricsResponse),
	}
}

// AddIndexingData will add the indexing data for the give topic
func (sm *statusMetrics) AddIndexingData(args ArgsAddIndexingData) {
	sm.mut.Lock()
	defer sm.mut.Unlock()

	topic := camelToSnake(args.Topic)
	_, found := sm.metrics[topic]
	if !found {
		sm.metrics[topic] = &request.MetricsResponse{
			ErrorsCount: map[int]uint64{},
		}
	}

	sm.metrics[topic].OperationsCount++
	sm.metrics[topic].TotalIndexingTime += args.Duration
	sm.metrics[topic].TotalData += args.MessageLen

	isErrorCode := args.StatusCode >= http.StatusBadRequest
	if args.GotError || isErrorCode {
		sm.metrics[topic].TotalErrorsCount++
	}
	if isErrorCode {
		sm.metrics[topic].ErrorsCount[args.StatusCode]++
	}
}

// IncrementDRWAStaleUnfinalizedCount increments the counter for DRWA records
// that were found in isFinalized=false state beyond the expected finality window.
func (sm *statusMetrics) IncrementDRWAStaleUnfinalizedCount() {
	sm.mut.Lock()
	sm.drwaStaleUnfinalizedCount++
	sm.mut.Unlock()
}

// GetMetrics returns the metrics map
func (sm *statusMetrics) GetMetrics() map[string]*request.MetricsResponse {
	sm.mut.RLock()
	defer sm.mut.RUnlock()

	return sm.getAllUnprotected()
}

// GetMetricsForPrometheus returns the metrics in a prometheus format
func (sm *statusMetrics) GetMetricsForPrometheus() string {
	sm.mut.RLock()
	metrics := sm.getAllUnprotected()
	sm.mut.RUnlock()

	stringBuilder := strings.Builder{}

	for topicWithShardID, metricsData := range metrics {
		topic, shardIDStr := request.SplitTopicAndShardID(topicWithShardID)
		stringBuilder.WriteString(counterMetric(topic, totalData, shardIDStr, metricsData.TotalData))
		stringBuilder.WriteString(counterMetric(topic, errorsCount, shardIDStr, metricsData.TotalErrorsCount))
		stringBuilder.WriteString(counterMetric(topic, operationCount, shardIDStr, metricsData.OperationsCount))
		stringBuilder.WriteString(counterMetric(topic, totalTime, shardIDStr, uint64(metricsData.TotalIndexingTime.Milliseconds())))
		stringBuilder.WriteString(errorsMetric(topic, requestsErrors, shardIDStr, metricsData.ErrorsCount))
	}

	// Append DRWA stale unfinalized counter as a standalone gauge
	sm.mut.RLock()
	staleCount := sm.drwaStaleUnfinalizedCount
	sm.mut.RUnlock()
	stringBuilder.WriteString(fmt.Sprintf("# HELP drwa_stale_unfinalized_records_total Number of times stale unfinalized DRWA records were detected and recovered\n"))
	stringBuilder.WriteString(fmt.Sprintf("# TYPE drwa_stale_unfinalized_records_total counter\n"))
	stringBuilder.WriteString(fmt.Sprintf("drwa_stale_unfinalized_records_total %d\n", staleCount))

	return stringBuilder.String()
}

func (sm *statusMetrics) getAllUnprotected() map[string]*request.MetricsResponse {
	newMap := make(map[string]*request.MetricsResponse)
	for key, value := range sm.metrics {
		newMap[key] = value
	}

	return newMap
}

// IsInterfaceNil returns true if there is no value under the interface
func (sm *statusMetrics) IsInterfaceNil() bool {
	return sm == nil
}

func camelToSnake(camelStr string) string {
	var snakeBuf bytes.Buffer

	for i, r := range camelStr {
		if unicode.IsUpper(r) {
			if i > 0 && unicode.IsLower(rune(camelStr[i-1])) {
				snakeBuf.WriteRune('_')
			}
			snakeBuf.WriteRune(unicode.ToLower(r))
		} else {
			snakeBuf.WriteRune(r)
		}
	}

	return snakeBuf.String()
}
