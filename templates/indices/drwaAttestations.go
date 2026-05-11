package indices

// DrwaAttestations will hold the configuration for the drwa-attestations index
var DrwaAttestations = Object{
	"index_patterns": Array{
		"drwa-attestations-*",
	},
	"template": Object{
		"settings": Object{
			"number_of_shards":   3,
			"number_of_replicas": 0,
		},
		"mappings": Object{
			"properties": Object{
				"txHash": Object{
					"type": "keyword",
				},
				"tokenId": Object{
					"type": "keyword",
				},
				"subject": Object{
					"type": "keyword",
				},
				"auditor": Object{
					"type": "keyword",
				},
				"eventType": Object{
					"type": "keyword",
				},
				"attestationType": Object{
					"type": "keyword",
				},
				"approved": Object{
					"type": "boolean",
				},
				"attestedRound": Object{
					"type": "long",
				},
				"blockHash": Object{
					"type": "keyword",
				},
				"blockRound": Object{
					"type": "long",
				},
				"isFinalized": Object{
					"type": "boolean",
				},
				"shardID": Object{
					"type": "long",
				},
				"eventOrder": Object{
					"type": "long",
				},
				"timestamp": Object{
					"type":   "date",
					"format": "epoch_second",
				},
				"timestampMs": Object{
					"type":   "date",
					"format": "epoch_millis",
				},
			},
		},
	},
}
