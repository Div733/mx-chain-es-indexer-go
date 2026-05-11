# Bug Fix Report: TestDRWAIdentityRecordFinalizedThenRemovedOnRevert

## Overview

The integration test `TestDRWAIdentityRecordFinalizedThenRemovedOnRevert` was failing. The test
validates the full lifecycle of a DRWA identity record:

1. Index a DRWA identity event via `SaveTransactions`
2. Verify the document is stored with the correct `blockHash` and `blockRound`, and `isFinalized` is absent
3. Call `FinalizedBlock` and verify `isFinalized` becomes `true`
4. Call `RemoveTransactions` (revert) and verify the document is deleted

Six separate issues were identified and fixed across the codebase. Additionally, the ES container
was crashing due to a kernel/JVM incompatibility, which caused all tests to fail.

---

## Issue 1 — `blockHash` was always empty in DRWA records

### File
`process/elasticproc/elasticProcessor.go`

### Root Cause
In `SaveTransactions`, the `headerData` struct was built without `HeaderHash`:

```go
// BEFORE
headerData := &data.HeaderData{
    Timestamp:   ...,
    Round:       ...,
    ShardID:     ...,
    // HeaderHash missing
}
```

Inside `prepareAndSaveTransactionsData`, the block hash is computed as:
```go
blockHashHex := hex.EncodeToString(headerData.HeaderHash)
```

With `HeaderHash` being `nil`, `blockHashHex` was always `""`. Every DRWA record was stored with
`blockHash: ""`. The test's first assertion checked `source["blockHash"] == hex.EncodeToString(headerHash)`,
which could never be satisfied.

### Fix
Added `HeaderHash: obh.BlockData.HeaderHash` to the `headerData` initialisation in `SaveTransactions`.

```go
// AFTER
headerData := &data.HeaderData{
    Timestamp:   ...,
    Round:       ...,
    ShardID:     ...,
    HeaderHash:  obh.BlockData.HeaderHash, // added
}
```

### Was it necessary?
Yes. Without this, DRWA records never stored the block hash, making `FinalizedBlock` unable to
match and update them, and making the first test assertion permanently fail.

---

## Issue 2 — DRWA ES indices were never created

### File
`process/elasticproc/templatesAndPolicies/reader.go`

### Root Cause
`GetElasticTemplatesAndPolicies` builds the `indexTemplates` map that drives `createIndices`.
All six DRWA index templates (`DrwaDenials`, `DrwaIdentities`, `DrwaHolderCompliance`,
`DrwaAttestations`, `DrwaTokenPolicies`, `DrwaControlEvents`) were missing from this map.
Elasticsearch never created those indices, so any operation against them returned HTTP 404.

### Fix
Added all six DRWA index templates to the map:

```go
indexTemplates[indexer.DrwaDenialsIndex]          = indices.DrwaDenials.ToBuffer()
indexTemplates[indexer.DrwaIdentitiesIndex]       = indices.DrwaIdentities.ToBuffer()
indexTemplates[indexer.DrwaHolderComplianceIndex] = indices.DrwaHolderCompliance.ToBuffer()
indexTemplates[indexer.DrwaAttestationsIndex]     = indices.DrwaAttestations.ToBuffer()
indexTemplates[indexer.DrwaTokenPoliciesIndex]    = indices.DrwaTokenPolicies.ToBuffer()
indexTemplates[indexer.DrwaControlEventsIndex]    = indices.DrwaControlEvents.ToBuffer()
```

### Was it necessary?
Yes. Without this, `FinalizedBlock` returned a 404 error on the first DRWA index it tried to
update, failing the test at the `require.NoError` after `FinalizedBlock`.

---

## Issue 3 — `RemoveTransactions` did not remove DRWA records on revert

### File
`process/elasticproc/elasticProcessor.go`

### Root Cause
`RemoveTransactions` handled transactions, SCRs, logs, events, and delegators on revert, but
never touched any DRWA index. The test's third assertion (`!found` after revert) could never
be satisfied because the DRWA identity document was never deleted.

### Fix — Part A: Use `blockHash`-based removal (matching the reference implementation)
Added a new method `removeFromIndexByBlockHashAndShardID` that deletes documents matching both
`blockHash` and `shardID` — more precise than timestamp-based removal since a block hash
uniquely identifies the reverted block:

```go
func (ei *elasticProcessor) removeFromIndexByBlockHashAndShardID(shardID uint32, index string, blockHash string) error {
    query, _ := json.Marshal(map[string]interface{}{
        "query": map[string]interface{}{
            "bool": map[string]interface{}{
                "must": []interface{}{
                    map[string]interface{}{"term": map[string]interface{}{"shardID": shardID}},
                    map[string]interface{}{"term": map[string]interface{}{"blockHash": blockHash}},
                },
            },
        },
    })
    ...
}
```

### Fix — Part B: Call it from `RemoveTransactions`
Added a loop in `RemoveTransactions` that computes the header hash and removes DRWA records
from all enabled DRWA indices:

```go
headerHash, err := ei.blockProc.ComputeHeaderHash(header)
blockHashHex := hex.EncodeToString(headerHash)

for _, index := range drwaIndices {
    if !ei.isIndexEnabled(index) { continue }
    err = ei.removeFromIndexByBlockHashAndShardID(header.GetShardID(), index, blockHashHex)
}
```

### Was it necessary?
Yes. Without this, DRWA records were never cleaned up on chain revert, causing the third
assertion to time out.

---

## Issue 4 — `UpdateByQuery` had no refresh, causing stale reads

### File
`client/elasticClient.go`

### Root Cause
`UpdateByQuery` was called immediately after `DoBulkRequest` (which indexed the DRWA record).
Elasticsearch's default refresh interval is 1 second, so the newly indexed document was not
yet visible to the `UpdateByQuery` term search. The update matched zero documents, leaving
`isFinalized` unset.

The reference implementation calls `doRefresh(index)` before `UpdateByQuery` to force the
index to be searchable before the update runs.

### Fix
Added `doRefresh` call at the start of `UpdateByQuery`:

```go
func (ec *elasticClient) UpdateByQuery(ctx context.Context, index string, buff *bytes.Buffer) error {
    err := ec.doRefresh(index)  // added
    if err != nil {
        log.Warn("elasticClient.doRefresh", "cannot do refresh", err)
    }
    res, err := ec.client.UpdateByQuery(...)
    ...
}
```

### Was it necessary?
Yes. Without the refresh, `UpdateByQuery` ran against a stale index snapshot and found no
matching documents, so `isFinalized` was never set to `true`.

---

## Issue 5 — `UpdateByQuery` returned 409 version conflict on repeated runs

### File
`client/elasticClient.go`

### Root Cause
When the test was run more than once against the same ES instance (without cleanup), the DRWA
document from a previous run still existed with a higher sequence number. Elasticsearch's
`update_by_query` uses optimistic concurrency by default and returns a 409 version conflict
when the document's sequence number doesn't match the snapshot taken at query start.

The reference implementation passes `WithConflicts("proceed")` to ignore version conflicts
and continue updating.

### Fix
Added `WithConflicts(esConflictsPolicy)` to `UpdateByQuery` (the constant `esConflictsPolicy`
is already defined as `"proceed"` in the file):

```go
res, err := ec.client.UpdateByQuery(
    []string{index},
    ec.client.UpdateByQuery.WithBody(buff),
    ec.client.UpdateByQuery.WithConflicts(esConflictsPolicy), // added
    ec.client.UpdateByQuery.WithContext(ctx),
)
```

### Was it necessary?
Yes. Without this, repeated test runs against a non-clean ES instance failed with a 409 error
at the `FinalizedBlock` step.

---

## Issue 6 — Test used a 32-byte bech32 emitter address; open-mode processor requires empty-string sentinel

### File
`integrationtests/drwa_finality_reorg_test.go`

### Root Cause
The test used `decodeAddress(drwaTestEmitter)` (a valid 32-byte address) as the log address.
The `logsAndEventsProcessor` is created with `newDRWAEventsProcessorOpenMode()`, which stores
`{"": {}}` in `authorizedEmitters`. The `isAuthorizedEmitter` check looks for
`string(logAddress)` in the map, then falls back to the `""` sentinel for open mode.

With a 32-byte decoded address, `string(logAddress)` is a 32-byte binary string — not `""` —
so the sentinel check correctly allows it. However, the `SilentEncode` call on this address
for the log record produced noisy warnings and, more importantly, the reference implementation
uses `[]byte("drwa-registry")` (a short arbitrary string) which is simpler and avoids the
bech32 encoding path entirely.

Additionally, the test lacked cleanup between runs, so stale documents from previous runs
interfered with assertions.

### Fix — Part A: Use `[]byte("drwa-registry")` as log address
```go
// BEFORE
Address: decodeAddress(drwaTestEmitter),

// AFTER
Address: []byte("drwa-registry"),
```

### Fix — Part B: Add pre-test cleanup and `t.Cleanup`
```go
docID := txHashHex + "-" + subject + "-drwaIdentityRegistered-0"

_ = deleteDocumentByID(esClient, indexerdata.DrwaIdentitiesIndex, docID)
t.Cleanup(func() {
    _ = deleteDocumentByID(esClient, indexerdata.DrwaIdentitiesIndex, docID)
})
```

### Was it necessary?
The address change is not strictly necessary (the open-mode sentinel allows any address), but
it matches the reference and avoids misleading bech32 warnings. The cleanup is necessary for
test isolation across repeated runs.

---

## Issue 7 — `deleteDocumentByID` helper was missing

### File
`integrationtests/utils.go`

### Root Cause
The cleanup in the test calls `deleteDocumentByID`, which did not exist in `utils.go`.

### Fix
Added the helper function (and required `bytes` and `context` imports):

```go
func deleteDocumentByID(esClient elasticproc.DatabaseClientHandler, index string, id string) error {
    body, _ := json.Marshal(map[string]interface{}{
        "query": map[string]interface{}{
            "ids": map[string]interface{}{"values": []string{id}},
        },
    })
    return esClient.DoQueryRemove(context.Background(), index, bytes.NewBuffer(body))
}
```

### Was it necessary?
Yes. The test would not compile without it.

---

## Issue 8 — ES 7.16.2 crashes on this kernel (all tests failing)

### File
`scripts/script.sh`

### Root Cause
`make integration-tests` calls `scripts/script.sh start` which pulls and runs
`elasticsearch:7.16.2`. This version bundles a JDK that crashes immediately on Linux kernels
with cgroup v2 enabled:

```
Exception in thread "main" java.lang.NullPointerException:
Cannot invoke "jdk.internal.platform.CgroupInfo.getMountPoint()"
because "anyController" is null
    at CgroupV2Subsystem.getInstance(CgroupV2Subsystem.java:81)
    at JvmOptionsParser.main(JvmOptionsParser.java:86)
```

The container exits with code 1 before ES starts, so all tests fail with
`dial tcp 127.0.0.1:9200: connect: connection refused`.

ES 7.17.x includes the JDK fix for this cgroup v2 issue.

### Fix
Updated `DEFAULT_ES_VERSION` in `scripts/script.sh`:

```bash
# BEFORE
DEFAULT_ES_VERSION=7.16.2

# AFTER
DEFAULT_ES_VERSION=7.17.28
```

### Was it necessary?
Yes. Without this, `make integration-tests` always fails on this system regardless of any
code changes.

---

## Summary of Changed Files

| File | Change | Necessary |
|------|--------|-----------|
| `process/elasticproc/elasticProcessor.go` | Added `HeaderHash` to `headerData` in `SaveTransactions`; added `removeFromIndexByBlockHashAndShardID`; used it in `RemoveTransactions` for DRWA revert | Yes |
| `process/elasticproc/templatesAndPolicies/reader.go` | Registered all 6 DRWA index templates | Yes |
| `client/elasticClient.go` | Added `doRefresh` + `WithConflicts` to `UpdateByQuery` | Yes |
| `integrationtests/drwa_finality_reorg_test.go` | Used `[]byte("drwa-registry")` as emitter; added cleanup; moved `docID` declaration earlier | Partially (cleanup is necessary; address change is a best-practice alignment) |
| `integrationtests/utils.go` | Added `deleteDocumentByID` helper | Yes |
| `scripts/script.sh` | Updated default ES version from 7.16.2 to 7.17.28 | Yes |

## Test Result

```
ok  github.com/multiversx/mx-chain-es-indexer-go/integrationtests  18.442s
```

All 45 integration tests pass.
