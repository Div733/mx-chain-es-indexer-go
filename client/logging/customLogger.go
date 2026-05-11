package logging

import (
	"net/http"
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

	// Read sizes from the headers — never consume req.Body/res.Body here, or
	// the request would be sent without a body and downstream code could not
	// decode the response. Clamp -1 (unknown length) to 0 for cleaner logs.
	if req != nil && req.ContentLength > 0 {
		reqSize = req.ContentLength
	}
	if res != nil && res.ContentLength > 0 {
		resSize = res.ContentLength
	}

	if err != nil {
		log.Warn("elastic client", "error", err.Error())
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

// RequestBodyEnabled tells the elastic client whether the round-tripper
// will consume req.Body. We do not — we read req.ContentLength instead —
// so this returns false, which prevents the client from teeing the body
// for us and avoids the (now-removed) drain that was breaking real requests.
func (cl *CustomLogger) RequestBodyEnabled() bool {
	return false
}

// ResponseBodyEnabled mirrors RequestBodyEnabled for the response side.
func (cl *CustomLogger) ResponseBodyEnabled() bool {
	return false
}
