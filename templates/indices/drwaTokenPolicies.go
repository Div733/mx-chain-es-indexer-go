package indices

// DrwaTokenPolicies will hold the configuration for the drwa-token-policies index
var DrwaTokenPolicies = Object{
	"index_patterns": Array{
		"drwa-token-policies-*",
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
				"policyId": Object{
					"type": "keyword",
				},
				"regulated": Object{
					"type": "boolean",
				},
				"globalPause": Object{
					"type": "boolean",
				},
				"strictAuditorMode": Object{
					"type": "boolean",
				},
				"whitePaperCid": Object{
					"type": "keyword",
				},
				"registrationStatus": Object{
					"type": "keyword",
				},
				"windDownInitiated": Object{
					"type": "boolean",
				},
				"tokenPolicyVersion": Object{
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
