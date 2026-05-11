package check

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestQueryGetLastTxForToken_EscapesInputsAsJSONValues(t *testing.T) {
	t.Parallel()

	query := queryGetLastTxForToken(`token"}, "must_not": [{"match_all": {}}], "x":"`, `addr"}, "should": [{"match_all": {}}], "x":"`)

	var decoded map[string]interface{}
	if err := json.Unmarshal(query.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(query.String(), `token\"}, \"must_not\": [{\"match_all\": {}}], \"x\":\"`) {
		t.Fatalf("expected escaped token in query: %s", query.String())
	}
	if strings.Contains(query.String(), `"must_not":[{"match_all":{}}]`) {
		t.Fatalf("query contains injected must_not clause: %s", query.String())
	}
}

func TestQueryGetLastOperationForAddress_EscapesInputsAsJSONValues(t *testing.T) {
	t.Parallel()

	query := queryGetLastOperationForAddress(`addr"}, "minimum_should_match": 1, "x":"`)

	var decoded map[string]interface{}
	if err := json.Unmarshal(query.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(query.String(), `addr\"}, \"minimum_should_match\": 1, \"x\":\"`) {
		t.Fatalf("expected escaped address in query: %s", query.String())
	}
	if strings.Contains(query.String(), `"minimum_should_match":1`) {
		t.Fatalf("query contains injected minimum_should_match: %s", query.String())
	}
}
