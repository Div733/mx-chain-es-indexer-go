package data

// MrvAnchoredProofRecord is written to the mrv-anchored-proofs Elasticsearch index.
// It preserves the canonical report proof fields emitted by the MRV registry.
type MrvAnchoredProofRecord struct {
	TxHash               string `json:"txHash"`
	EventType            string `json:"eventType"`
	ReportID             string `json:"reportId"`
	PublicTenantID       string `json:"publicTenantId,omitempty"`
	PublicFarmID         string `json:"publicFarmId,omitempty"`
	PublicSeasonID       string `json:"publicSeasonId,omitempty"`
	PublicProjectID      string `json:"publicProjectId,omitempty"`
	ReportHash           string `json:"reportHash,omitempty"`
	HashAlgo             string `json:"hashAlgo,omitempty"`
	Canonicalization     string `json:"canonicalization,omitempty"`
	MethodologyVersion   uint64 `json:"methodologyVersion,omitempty"`
	AnchoredAt           uint64 `json:"anchoredAt,omitempty"`
	EvidenceManifestHash string `json:"evidenceManifestHash,omitempty"`
	BlockHash            string `json:"blockHash,omitempty"`
	BlockRound           uint64 `json:"blockRound,omitempty"`
	IsFinalized          bool   `json:"isFinalized,omitempty"`
	ShardID              uint32 `json:"shardID,omitempty"`
	EventOrder           int    `json:"eventOrder,omitempty"`
	Timestamp            uint64 `json:"timestamp,omitempty"`
	TimestampMs          uint64 `json:"timestampMs,omitempty"`
}
