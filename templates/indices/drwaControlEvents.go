package indices

// DrwaControlEvents will hold the configuration for the drwa-control-events index
var DrwaControlEvents = Object{
	"index_patterns": Array{
		"drwa-control-events-*",
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
				"eventType": Object{
					"type": "keyword",
				},
				"governance": Object{
					"type": "keyword",
				},
				"topics": Object{
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
