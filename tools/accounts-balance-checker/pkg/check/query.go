package check

import (
	"bytes"
	"encoding/json"
	"fmt"
)

type object = map[string]interface{}

const matchAllQuery = `{ "query": { "match_all": { } } }`

func encodeQuery(query object) (bytes.Buffer, error) {
	var buff bytes.Buffer
	if err := json.NewEncoder(&buff).Encode(query); err != nil {
		return bytes.Buffer{}, fmt.Errorf("error encoding query: %s", err.Error())
	}

	return buff, nil
}

func getDocumentsByIDsQuery(hashes []string, withSource bool) object {
	interfaceSlice := make([]string, 0, len(hashes))
	for idx := range hashes {
		interfaceSlice = append(interfaceSlice, hashes[idx])
	}

	return object{
		"query": object{
			"ids": object{
				"values": interfaceSlice,
			},
		},
		"_source": withSource,
	}
}

func getBalancesByAddress(addr string) object {
	return object{
		"query": object{
			"match": object{
				"address": addr,
			},
		},
	}
}

func queryGetLastTxForToken(identifier, addr string) (*bytes.Buffer, error) {
	query := object{
		"query": object{
			"bool": object{
				"must": []interface{}{
					object{"match": object{"tokens": object{"query": identifier, "operator": "AND"}}},
					object{"match": object{"sender": object{"query": addr, "operator": "AND"}}},
				},
			},
		},
		"sort": []interface{}{object{"timestamp": object{"order": "desc"}}},
	}
	encoded, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}
	return bytes.NewBuffer(encoded), nil
}

func queryGetLastOperationForAddress(addr string) (*bytes.Buffer, error) {
	query := object{
		"query": object{
			"bool": object{
				"should": []interface{}{
					object{"match": object{"sender": object{"query": addr, "operator": "AND"}}},
					object{"match": object{"receiver": object{"query": addr, "operator": "AND"}}},
				},
			},
		},
		"sort": []interface{}{object{"timestamp": object{"order": "desc"}}},
	}
	encoded, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}
	return bytes.NewBuffer(encoded), nil
}
