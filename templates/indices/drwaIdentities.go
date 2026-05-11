package indices

// DrwaIdentities will hold the configuration for the drwa-identities index
var DrwaIdentities = Object{
	"index_patterns": Array{
		"drwa-identities-*",
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
				"subject": Object{
					"type": "keyword",
				},
				"eventType": Object{
					"type": "keyword",
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
				"jurisdictionCode": Object{
					"type": "keyword",
				},
				"entityType": Object{
					"type": "keyword",
				},
				"kycStatus": Object{
					"type": "keyword",
				},
				"amlStatus": Object{
					"type": "keyword",
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
