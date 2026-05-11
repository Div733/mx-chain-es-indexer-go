package indices

// DrwaHolderCompliance will hold the configuration for the drwa-holder-compliance index
var DrwaHolderCompliance = Object{
	"index_patterns": Array{
		"drwa-holder-compliance-*",
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
				"holder": Object{
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
				"holderPolicyVersion": Object{
					"type": "long",
				},
				"kycStatus": Object{
					"type": "keyword",
				},
				"amlStatus": Object{
					"type": "keyword",
				},
				"investorClass": Object{
					"type": "keyword",
				},
				"jurisdictionCode": Object{
					"type": "keyword",
				},
				"transferLocked": Object{
					"type": "boolean",
				},
				"receiveLocked": Object{
					"type": "boolean",
				},
				"auditorAuthorized": Object{
					"type": "boolean",
				},
				"expiryRound": Object{
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
