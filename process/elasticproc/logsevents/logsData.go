package logsevents

import (
	"github.com/multiversx/mx-chain-es-indexer-go/data"
	"github.com/multiversx/mx-chain-es-indexer-go/process/elasticproc/converters"
	"github.com/multiversx/mx-chain-es-indexer-go/process/elasticproc/tokeninfo"
)

type logsData struct {
	timestamp               uint64
	timestampMs             uint64
	txHashStatusInfoProc    txHashStatusInfoHandler
	tokens                  data.TokensHandler
	tokensSupply            data.TokensHandler
	txsMap                  map[string]*data.Transaction
	scrsMap                 map[string]*data.ScResult
	scDeploys               map[string]*data.ScDeployInfo
	changeOwnerOperations   map[string]*data.OwnerData
	delegators              map[string]*data.Delegator
	tokensInfo              []*data.TokenInfo
	nftsDataUpdates         []*data.NFTDataUpdate
	tokenRolesAndProperties *tokeninfo.TokenRolesAndProperties
	drwaDenials             []*data.DrwaDenialRecord
	drwaIdentities          []*data.DrwaIdentityRecord
	drwaHolderCompliances   []*data.DrwaHolderComplianceRecord
	drwaAttestations        []*data.DrwaAttestationRecord
	drwaTokenPolicies       []*data.DrwaTokenPolicyRecord
	drwaControlEvents       []*data.DrwaControlEventRecord
}

func newLogsData(
	txs []*data.Transaction,
	scrs []*data.ScResult,
	timestampMs uint64,
) *logsData {
	ld := &logsData{}

	ld.txsMap = converters.ConvertTxsSliceIntoMap(txs)
	ld.scrsMap = converters.ConvertScrsSliceIntoMap(scrs)
	ld.tokens = data.NewTokensInfo()
	ld.tokensSupply = data.NewTokensInfo()
	ld.timestamp = converters.MillisecondsToSeconds(timestampMs)
	ld.scDeploys = make(map[string]*data.ScDeployInfo)
	ld.tokensInfo = make([]*data.TokenInfo, 0)
	ld.delegators = make(map[string]*data.Delegator)
	ld.changeOwnerOperations = make(map[string]*data.OwnerData)
	ld.nftsDataUpdates = make([]*data.NFTDataUpdate, 0)
	ld.tokenRolesAndProperties = tokeninfo.NewTokenRolesAndProperties()
	ld.txHashStatusInfoProc = newTxHashStatusInfoProcessor()
	ld.timestampMs = timestampMs
	ld.drwaDenials = make([]*data.DrwaDenialRecord, 0)
	ld.drwaIdentities = make([]*data.DrwaIdentityRecord, 0)
	ld.drwaHolderCompliances = make([]*data.DrwaHolderComplianceRecord, 0)
	ld.drwaAttestations = make([]*data.DrwaAttestationRecord, 0)
	ld.drwaTokenPolicies = make([]*data.DrwaTokenPolicyRecord, 0)
	ld.drwaControlEvents = make([]*data.DrwaControlEventRecord, 0)

	return ld
}
