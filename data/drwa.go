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
	ShardID     uint32 `json:"shardId,omitempty"`
	Timestamp   uint64 `json:"timestamp,omitempty"`
	TimestampMs uint64 `json:"timestampMs,omitempty"`
}

// DrwaHolderComplianceRecord is a persistent record for a holder compliance mirror update.
// Written to the drwa-holder-compliance Elasticsearch index.
type DrwaHolderComplianceRecord struct {
	TxHash               string `json:"txHash"`
	TokenID              string `json:"tokenId"`
	Holder               string `json:"holder"`
	HolderPolicyVersion  uint64 `json:"holderPolicyVersion,omitempty"`
	KYCStatus            string `json:"kycStatus,omitempty"`
	AMLStatus            string `json:"amlStatus,omitempty"`
	InvestorClass        string `json:"investorClass,omitempty"`
	JurisdictionCode     string `json:"jurisdictionCode,omitempty"`
	TransferLocked       bool   `json:"transferLocked,omitempty"`
	ReceiveLocked        bool   `json:"receiveLocked,omitempty"`
	AuditorAuthorized    bool   `json:"auditorAuthorized,omitempty"`
	ExpiryRound          uint64 `json:"expiryRound,omitempty"`
	Timestamp            uint64 `json:"timestamp,omitempty"`
	TimestampMs          uint64 `json:"timestampMs,omitempty"`
}

// DrwaAttestationRecord is a persistent record for a DRWA attestation event.
// Written to the drwa-attestations Elasticsearch index.
type DrwaAttestationRecord struct {
	TxHash      string `json:"txHash"`
	TokenID     string `json:"tokenId,omitempty"`
	Subject     string `json:"subject,omitempty"`
	Auditor     string `json:"auditor"`
	EventType   string `json:"eventType"` // drwaAuditorAccepted, drwaAuditorProposed
	Approved    bool   `json:"approved,omitempty"`
	AttestedRound uint64 `json:"attestedRound,omitempty"`
	Timestamp   uint64 `json:"timestamp,omitempty"`
	TimestampMs uint64 `json:"timestampMs,omitempty"`
}

// DrwaTokenPolicyRecord is a persistent record for DRWA token policy history.
// Written to the drwa-token-policies Elasticsearch index.
type DrwaTokenPolicyRecord struct {
	TxHash             string `json:"txHash"`
	TokenID            string `json:"tokenId"`
	EventType          string `json:"eventType"`
	PolicyID           string `json:"policyId,omitempty"`
	Regulated          bool   `json:"regulated,omitempty"`
	GlobalPause        bool   `json:"globalPause,omitempty"`
	StrictAuditorMode  bool   `json:"strictAuditorMode,omitempty"`
	TokenPolicyVersion uint64 `json:"tokenPolicyVersion,omitempty"`
	Timestamp          uint64 `json:"timestamp,omitempty"`
	TimestampMs        uint64 `json:"timestampMs,omitempty"`
}
