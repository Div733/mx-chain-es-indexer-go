package logging

import "testing"

func TestCustomLogger_RequestBodyDisabled(t *testing.T) {
	t.Parallel()

	logger := &CustomLogger{}
	if logger.RequestBodyEnabled() {
		t.Fatal("request body logging should be disabled when bodies are not consumed")
	}
}

func TestCustomLogger_ResponseBodyDisabled(t *testing.T) {
	t.Parallel()

	logger := &CustomLogger{}
	if logger.ResponseBodyEnabled() {
		t.Fatal("response body logging should be disabled when bodies are not consumed")
	}
}
