package data

// DRWAEventMaterialization contains DRWA-specific event extraction metadata.
type DRWAEventMaterialization struct {
	TxHash        string   `json:"txHash"`
	Identifier    string   `json:"identifier"`
	TokenID       string   `json:"tokenId,omitempty"`
	Holder        string   `json:"holder,omitempty"`
	PolicyVersion uint64   `json:"policyVersion,omitempty"`
	DenialCode    string   `json:"denialCode,omitempty"`
	Topics        []string `json:"topics,omitempty"`
	Timestamp     uint64   `json:"timestamp,omitempty"`
	TimestampMs   uint64   `json:"timestampMs,omitempty"`
}

// DrwaDenialRecord is a persistent record for a single regulated transfer denial.
// Written to the drwa-denials Elasticsearch index.
type DrwaDenialRecord struct {
	TxHash      string `json:"txHash"`
	TokenID     string `json:"tokenId"`
	Sender      string `json:"sender,omitempty"`
	Receiver    string `json:"receiver,omitempty"`
	DenialCode  string `json:"denialCode"`
	BlockHash   string `json:"blockHash,omitempty"`
	BlockRound  uint64 `json:"blockRound,omitempty"`
	IsFinalized bool   `json:"isFinalized,omitempty"`
	ShardID     uint32 `json:"shardID,omitempty"`
	EventOrder  int    `json:"eventOrder,omitempty"`
	Timestamp   uint64 `json:"timestamp,omitempty"`
	TimestampMs uint64 `json:"timestampMs,omitempty"`
}

// DrwaHolderComplianceRecord is a persistent record for a holder compliance mirror update.
// Written to the drwa-holder-compliance Elasticsearch index.
type DrwaHolderComplianceRecord struct {
	TxHash              string `json:"txHash"`
	TokenID             string `json:"tokenId"`
	Holder              string `json:"holder"`
	BlockHash           string `json:"blockHash,omitempty"`
	BlockRound          uint64 `json:"blockRound,omitempty"`
	IsFinalized         bool   `json:"isFinalized,omitempty"`
	ShardID             uint32 `json:"shardID,omitempty"`
	EventOrder          int    `json:"eventOrder,omitempty"`
	HolderPolicyVersion uint64 `json:"holderPolicyVersion,omitempty"`
	KYCStatus           string `json:"kycStatus,omitempty"`
	AMLStatus           string `json:"amlStatus,omitempty"`
	InvestorClass       string `json:"investorClass,omitempty"`
	JurisdictionCode    string `json:"jurisdictionCode,omitempty"`
	TransferLocked      bool   `json:"transferLocked,omitempty"`
	ReceiveLocked       bool   `json:"receiveLocked,omitempty"`
	AuditorAuthorized   *bool  `json:"auditorAuthorized,omitempty"`
	ExpiryRound         uint64 `json:"expiryRound,omitempty"`
	Timestamp           uint64 `json:"timestamp,omitempty"`
	TimestampMs         uint64 `json:"timestampMs,omitempty"`
}

// DrwaIdentityRecord is a persistent record for DRWA identity lifecycle events.
// Written to the drwa-identities Elasticsearch index.
//
// Important: this record intentionally contains only fields emitted by the
// contract events. It is an event-history projection, not a full identity
// snapshot.
type DrwaIdentityRecord struct {
	TxHash           string `json:"txHash"`
	Subject          string `json:"subject"`
	EventType        string `json:"eventType"`
	BlockHash        string `json:"blockHash,omitempty"`
	BlockRound       uint64 `json:"blockRound,omitempty"`
	IsFinalized      bool   `json:"isFinalized,omitempty"`
	ShardID          uint32 `json:"shardID,omitempty"`
	EventOrder       int    `json:"eventOrder,omitempty"`
	JurisdictionCode string `json:"jurisdictionCode,omitempty"`
	EntityType       string `json:"entityType,omitempty"`
	KYCStatus        string `json:"kycStatus,omitempty"`
	AMLStatus        string `json:"amlStatus,omitempty"`
	Timestamp        uint64 `json:"timestamp,omitempty"`
	TimestampMs      uint64 `json:"timestampMs,omitempty"`
}

// DrwaAttestationRecord is a persistent record for a DRWA attestation event.
// Written to the drwa-attestations Elasticsearch index.
type DrwaAttestationRecord struct {
	TxHash          string `json:"txHash"`
	TokenID         string `json:"tokenId,omitempty"`
	Subject         string `json:"subject,omitempty"`
	Auditor         string `json:"auditor"`
	EventType       string `json:"eventType"` // drwaAuditorAccepted, drwaAuditorProposed
	AttestationType string `json:"attestationType,omitempty"`
	Approved        bool   `json:"approved,omitempty"`
	AttestedRound   uint64 `json:"attestedRound,omitempty"`
	BlockHash       string `json:"blockHash,omitempty"`
	BlockRound      uint64 `json:"blockRound,omitempty"`
	IsFinalized     bool   `json:"isFinalized,omitempty"`
	ShardID         uint32 `json:"shardID,omitempty"`
	EventOrder      int    `json:"eventOrder,omitempty"`
	Timestamp       uint64 `json:"timestamp,omitempty"`
	TimestampMs     uint64 `json:"timestampMs,omitempty"`
}

// DrwaTokenPolicyRecord is a persistent record for DRWA token policy history.
// Written to the drwa-token-policies Elasticsearch index.
type DrwaTokenPolicyRecord struct {
	TxHash             string `json:"txHash"`
	TokenID            string `json:"tokenId"`
	EventType          string `json:"eventType"`
	BlockHash          string `json:"blockHash,omitempty"`
	BlockRound         uint64 `json:"blockRound,omitempty"`
	IsFinalized        bool   `json:"isFinalized,omitempty"`
	ShardID            uint32 `json:"shardID,omitempty"`
	EventOrder         int    `json:"eventOrder,omitempty"`
	PolicyID           string `json:"policyId,omitempty"`
	Regulated          bool   `json:"regulated,omitempty"`
	GlobalPause        bool   `json:"globalPause,omitempty"`
	StrictAuditorMode  bool   `json:"strictAuditorMode,omitempty"`
	WhitePaperCID      string `json:"whitePaperCid,omitempty"`
	RegistrationStatus string `json:"registrationStatus,omitempty"`
	WindDownInitiated  bool   `json:"windDownInitiated,omitempty"`
	TokenPolicyVersion uint64 `json:"tokenPolicyVersion,omitempty"`
	Timestamp          uint64 `json:"timestamp,omitempty"`
	TimestampMs        uint64 `json:"timestampMs,omitempty"`
}

// DrwaControlEventRecord is a generic persistent record for DRWA governance and
// other control-plane events whose topic schema is only partially standardized
// in the checked-in repository state.
type DrwaControlEventRecord struct {
	TxHash      string   `json:"txHash"`
	EventType   string   `json:"eventType"`
	Governance  string   `json:"governance,omitempty"`
	Topics      []string `json:"topics,omitempty"`
	BlockHash   string   `json:"blockHash,omitempty"`
	BlockRound  uint64   `json:"blockRound,omitempty"`
	IsFinalized bool     `json:"isFinalized,omitempty"`
	ShardID     uint32   `json:"shardID,omitempty"`
	EventOrder  int      `json:"eventOrder,omitempty"`
	Timestamp   uint64   `json:"timestamp,omitempty"`
	TimestampMs uint64   `json:"timestampMs,omitempty"`
}
