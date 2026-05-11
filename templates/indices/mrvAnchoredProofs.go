package indices

// MrvAnchoredProofs will hold the configuration for the mrv-anchored-proofs index.
var MrvAnchoredProofs = Object{
	"index_patterns": Array{
		"mrv-anchored-proofs-*",
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
				"reportId": Object{
					"type": "keyword",
				},
				"publicTenantId": Object{
					"type": "keyword",
				},
				"publicFarmId": Object{
					"type": "keyword",
				},
				"publicSeasonId": Object{
					"type": "keyword",
				},
				"publicProjectId": Object{
					"type": "keyword",
				},
				"reportHash": Object{
					"type": "keyword",
				},
				"hashAlgo": Object{
					"type": "keyword",
				},
				"canonicalization": Object{
					"type": "keyword",
				},
				"methodologyVersion": Object{
					"type": "long",
				},
				"anchoredAt": Object{
					"type": "long",
				},
				"evidenceManifestHash": Object{
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
