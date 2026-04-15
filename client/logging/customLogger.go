package logging

import (
	"io"
	"net/http"
	"strings"
	"time"

	logger "github.com/multiversx/mx-chain-logger-go"
)

var log = logger.GetOrCreate("indexer/client/requests")

// CustomLogger defines a custom logger for the elastic client
type CustomLogger struct{}

// LogRoundTrip logs useful information about the client request and response
func (cl *CustomLogger) LogRoundTrip(
	req *http.Request,
	res *http.Response,
	err error,
	_ time.Time,
	dur time.Duration,
) error {
	var (
		reqSize int64
		resSize int64
	)

	if req != nil && req.Body != nil && req.Body != http.NoBody {
		reqSize, _ = io.Copy(io.Discard, req.Body)
	}
	if res != nil && res.Body != nil && res.Body != http.NoBody {
		resSize, _ = io.Copy(io.Discard, res.Body)
	}

	if err != nil {
		log.Warn("elastic client", "error", sanitizeLogMessage(err.Error()))
	}

	if req != nil && res != nil {
		logInformation(req, res, err, dur, reqSize, resSize)
	}

	return nil
}

func logInformation(
	req *http.Request,
	res *http.Response,
	err error,
	dur time.Duration,
	reqSize int64,
	resSize int64,
) {
	logData := []interface{}{
		"method", req.Method,
		"status code", res.StatusCode,
		"duration", dur,
		"request bytes", reqSize,
		"response bytes", resSize,
		"URL", req.URL.String(),
	}
	if err != nil {
		log.Warn("elastic client", logData...)
		return
	}

	log.Debug("elastic client", logData...)
}

func sanitizeLogMessage(msg string) string {
	msg = strings.ReplaceAll(msg, "\n", " ")
	msg = strings.ReplaceAll(msg, "\r", " ")
	msg = strings.ReplaceAll(msg, "\t", " ")
	if len(msg) > 500 {
		msg = msg[:500] + "...[truncated]"
	}
	return msg
}

// RequestBodyEnabled makes the client pass request body to logger
func (cl *CustomLogger) RequestBodyEnabled() bool {
	return true
}

// ResponseBodyEnabled makes the client pass response body to logger
func (cl *CustomLogger) ResponseBodyEnabled() bool {
	return true
}
