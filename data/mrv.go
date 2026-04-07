package data

// MRVProofMaterialization contains MRV-specific proof extraction metadata.
// T-41: Updated to include all fields expected by mx-api-service MrvProofDocument entity.
// Fields added: PublicProjectID, EvidenceManifestHash, IndexedAt, SourceEventName.
type MRVProofMaterialization struct {
	ReportID             string `json:"reportId"`
	PublicTenantID       string `json:"publicTenantId,omitempty"`
	PublicFarmID         string `json:"publicFarmId,omitempty"`
	PublicSeasonID       string `json:"publicSeasonId,omitempty"`
	PublicProjectID      string `json:"publicProjectId,omitempty"`
	ReportHash           string `json:"reportHash,omitempty"`
	HashAlgo             string `json:"hashAlgo,omitempty"`
	Canonicalization     string `json:"canonicalization,omitempty"`
	MethodologyVersion   uint64 `json:"methodologyVersion,omitempty"`
	EvidenceManifestHash string `json:"evidenceManifestHash,omitempty"`
	ProofStatus          string `json:"proofStatus,omitempty"`
	AnchoredAt           uint64 `json:"anchoredAt,omitempty"`
	IndexedAt            uint64 `json:"indexedAt,omitempty"`
	SourceEventName      string `json:"sourceEventName,omitempty"`
	Timestamp            uint64 `json:"timestamp,omitempty"`
	TimestampMs          uint64 `json:"timestampMs,omitempty"`
}
