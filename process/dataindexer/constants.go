package dataindexer

const (
	// IndexSuffix is the suffix for the Elasticsearch indexes
	IndexSuffix = "000001"
	// BlockIndex is the Elasticsearch index for the blocks
	BlockIndex = "blocks"
	// MiniblocksIndex is the Elasticsearch index for the miniblocks
	MiniblocksIndex = "miniblocks"
	// TransactionsIndex is the Elasticsearch index for the transactions
	TransactionsIndex = "transactions"
	// ValidatorsIndex is the Elasticsearch index for the validators information
	ValidatorsIndex = "validators"
	// RoundsIndex is the Elasticsearch index for the rounds information
	RoundsIndex = "rounds"
	// RatingIndex is the Elasticsearch index for the rating information
	RatingIndex = "rating"
	// AccountsIndex is the Elasticsearch index for the accounts
	AccountsIndex = "accounts"
	// AccountsHistoryIndex is the Elasticsearch index for the accounts history information
	AccountsHistoryIndex = "accountshistory"
	// ReceiptsIndex is the Elasticsearch index for the receipts
	ReceiptsIndex = "receipts"
	// ScResultsIndex is the Elasticsearch index for the smart contract results
	ScResultsIndex = "scresults"
	// AccountsESDTIndex is the Elasticsearch index for the accounts with ESDT balance
	AccountsESDTIndex = "accountsesdt"
	// AccountsESDTHistoryIndex is the Elasticsearch index for the accounts history information with ESDT balance
	AccountsESDTHistoryIndex = "accountsesdthistory"
	// EpochInfoIndex is the Elasticsearch index for the epoch information
	EpochInfoIndex = "epochinfo"
	// OpenDistroIndex is the Elasticsearch index for opendistro
	OpenDistroIndex = "opendistro"
	// SCDeploysIndex is the Elasticsearch index for the smart contracts deploy information
	SCDeploysIndex = "scdeploys"
	// TokensIndex is the Elasticsearch index for the ESDT tokens
	TokensIndex = "tokens"
	// TagsIndex is the Elasticsearch index for NFTs tags
	TagsIndex = "tags"
	// LogsIndex is the Elasticsearch index for logs
	LogsIndex = "logs"
	// DelegatorsIndex is the Elasticsearch index for delegators
	DelegatorsIndex = "delegators"
	// OperationsIndex is the Elasticsearch index for transactions and smart contract results
	OperationsIndex = "operations"
	// ESDTsIndex is the Elasticsearch index for esdt tokens
	ESDTsIndex = "esdts"
	// ValuesIndex is the Elasticsearch index for extra indexer information
	ValuesIndex = "values"
	// EventsIndex is the Elasticsearch index for log events
	EventsIndex = "events"

	// DrwaDenialsIndex is the Elasticsearch index for DRWA regulated transfer denial history
	DrwaDenialsIndex = "drwa-denials"
	// DrwaHolderComplianceIndex is the Elasticsearch index for DRWA holder compliance update history
	DrwaHolderComplianceIndex = "drwa-holder-compliance"
	// DrwaAttestationsIndex is the Elasticsearch index for DRWA auditor attestation history
	DrwaAttestationsIndex = "drwa-attestations"
	// DrwaTokenPoliciesIndex is the Elasticsearch index for DRWA token policy history
	DrwaTokenPoliciesIndex = "drwa-token-policies"

	// DrwaDenialsPolicy is the Elasticsearch policy for DRWA denial records
	DrwaDenialsPolicy = "drwa-denials_policy"
	// DrwaHolderCompliancePolicy is the Elasticsearch policy for DRWA holder compliance records
	DrwaHolderCompliancePolicy = "drwa-holder-compliance_policy"
	// DrwaAttestationsPolicy is the Elasticsearch policy for DRWA attestation records
	DrwaAttestationsPolicy = "drwa-attestations_policy"
	// DrwaTokenPoliciesPolicy is the Elasticsearch policy for DRWA token policy history records
	DrwaTokenPoliciesPolicy = "drwa-token-policies_policy"

	// T-41: MrvProofsIndex is the Elasticsearch index for MRV proof materialization records
	MrvProofsIndex = "mrv-proofs"
	// MrvProofsPolicy is the Elasticsearch policy for MRV proof records
	MrvProofsPolicy = "mrv-proofs_policy"

	// TransactionsPolicy is the Elasticsearch policy for the transactions
	TransactionsPolicy = "transactions_policy"
	// BlockPolicy is the Elasticsearch policy for the blocks
	BlockPolicy = "blocks_policy"
	// MiniblocksPolicy is the Elasticsearch policy for the miniblocks
	MiniblocksPolicy = "miniblocks_policy"
	// ValidatorsPolicy is the Elasticsearch policy for the validators information
	ValidatorsPolicy = "validators_policy"
	// RoundsPolicy is the Elasticsearch policy for the rounds information
	RoundsPolicy = "rounds_policy"
	// RatingPolicy is the Elasticsearch policy for the rating information
	RatingPolicy = "rating_policy"
	// AccountsPolicy is the Elasticsearch policy for the accounts
	AccountsPolicy = "accounts_policy"
	// AccountsHistoryPolicy is the Elasticsearch policy for the accounts history information
	AccountsHistoryPolicy = "accountshistory_policy"
	// AccountsESDTPolicy is the Elasticsearch policy for the accounts with ESDT balance
	AccountsESDTPolicy = "accountsesdt_policy"
	// AccountsESDTHistoryPolicy is the Elasticsearch policy for the accounts history information with ESDT
	AccountsESDTHistoryPolicy = "accountsesdthistory_policy"
	// ScResultsPolicy is the Elasticsearch policy for the smart contract results
	ScResultsPolicy = "scresults_policy"
	// ReceiptsPolicy is the Elasticsearch policy for the receipts
	ReceiptsPolicy = "receipts_policy"
)
