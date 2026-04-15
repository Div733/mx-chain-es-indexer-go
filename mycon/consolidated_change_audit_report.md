# Consolidated Change Audit Report — DRWA & MRV Feature

**Repository:** mx-chain-es-indexer-go
**Feature/Domain:** RWA / DRWA (Dharitri Real World Assets) + MRV (Measurement, Reporting, Verification)

---

## Overview

This report consolidates individual change audit reports for all 17 files modified or created as part of the DRWA and MRV feature implementation. Each section follows the standard audit template and covers: change scope, system flow, invariant analysis, change explanation, failure & risk analysis, test analysis, cross-system impact, and final decision.

### File Index

| # | File | Change Type | Status |
|---|------|-------------|--------|
| 1 | `process/dataindexer/constants.go` | Feature | 🔴 HOLD |
| 2 | `data/drwa.go` | Feature (New File) | 🔴 HOLD |
| 3 | `data/drwa_test.go` | Test (New File) | 🟡 APPROVE w/ notes |
| 4 | `data/tokens.go` | Feature | 🔴 HOLD |
| 5 | `data/mrv.go` | Feature (New File) | 🔴 HOLD |
| 6 | `data/logs.go` | Feature | 🔴 HOLD |
| 7 | `process/elasticproc/logsevents/logsData.go` | Feature | 🟢 APPROVE |
| 8 | `process/elasticproc/logsevents/interface.go` | Feature | 🟢 APPROVE |
| 9 | `process/elasticproc/logsevents/drwaEventsProcessor.go` | Feature (New File) | 🔴 HOLD |
| 10 | `process/elasticproc/logsevents/drwaEventsProcessor_test.go` | Test (New File) | 🟡 APPROVE w/ notes |
| 11 | `process/elasticproc/logsevents/drwaEventsProcessor_benchmark_test.go` | Benchmark (New File) | 🟡 APPROVE w/ notes |
| 12 | `process/elasticproc/logsevents/logsAndEventsProcessor.go` | Feature + Refactor | 🟢 APPROVE |
| 13 | `process/elasticproc/logsevents/serialize.go` | Feature | 🔴 HOLD |
| 14 | `process/elasticproc/logsevents/serializeDrwa.go` | Feature (New File) | 🔴 HOLD |
| 15 | `process/elasticproc/logsevents/serialize_test.go` | Test Addition | 🟢 APPROVE |
| 16 | `process/elasticproc/interface.go` | Feature | 🟢 APPROVE |
| 17 | `process/elasticproc/elasticProcessor.go` | Feature + Refactor | 🔴 HOLD |

### Cross-Cutting Blockers (affect multiple files)

Before any DRWA/MRV data reaches Elasticsearch in production, four systemic issues must be resolved:

1. **`omitempty` on boolean fields (DRWA Golden Rule #3 — Consistency)** — affects `data/drwa.go`, `data/tokens.go`. Boolean fields that transition `true → false` are silently omitted from JSON, causing ES to drift from on-chain state — the ES equivalent of the sync drift failure scenario defined in the DRWA domain brief.
2. **DRWA/MRV indices never created on startup** — affects `process/dataindexer/constants.go`, `process/elasticproc/elasticProcessor.go`. The index constants are defined but never wired into the startup provisioning slices.
3. **Denial ID collision** — affects `process/elasticproc/logsevents/serializeDrwa.go`. Multiple denials with the same code in one transaction overwrite each other in ES.
4. **MRV schema missing Buffer Integrity and 8-Gate fields** — affects `data/mrv.go`. `MRVProofMaterialization` has no fields for buffer deduction status (Golden Rule #3) or gate-level verification results (G1–G8), making the ES audit trail unable to prove MRV compliance.

---

## 1. `process/dataindexer/constants.go`

### 1.1 Change Scope

- **Files Changed:** `process/dataindexer/constants.go`
- **Change Type:** Feature
- **New stored state:** No directly — constants are compile-time values. They are the single source of truth for 4 DRWA index names, 4 DRWA ILM policy names, 1 MRV index name, and 1 MRV policy name.

10 new string constants added:
```go
DrwaDenialsIndex          = "drwa-denials"
DrwaHolderComplianceIndex = "drwa-holder-compliance"
DrwaAttestationsIndex     = "drwa-attestations"
DrwaTokenPoliciesIndex    = "drwa-token-policies"
DrwaDenialsPolicy         = "drwa-denials_policy"
DrwaHolderCompliancePolicy = "drwa-holder-compliance_policy"
DrwaAttestationsPolicy    = "drwa-attestations_policy"
DrwaTokenPoliciesPolicy   = "drwa-token-policies_policy"
MrvProofsIndex            = "mrv-proofs"
MrvProofsPolicy           = "mrv-proofs_policy"
```

### 1.2 Impacted System Flow

- **Flow:** Indexer Startup → Elasticsearch Index & Policy Provisioning
- **Entry Point:** `elasticProcessor.init()` on startup
- **Exit Point:** Elasticsearch — indices and policies exist and are ready to receive bulk writes
- **Key detail:** `isIndexEnabled()` does a map lookup using these constant values. If a constant drifts from the actual index name in Elasticsearch, writes are silently skipped.

### 1.3 Invariant Analysis

- **Are invariants affected?** Yes — and currently broken.
- Every index constant must have a corresponding entry in the `indexes` slice in `elasticProcessor.go`. Every policy constant must have a corresponding entry in `indexesPolicies`. **None of the 10 new constants are wired into either slice.** `MrvProofsIndex` and `MrvProofsPolicy` are additionally dead constants — consumed nowhere.

### 1.4 Change Explanation

- **Before:** No named constants for DRWA or MRV infrastructure. Raw string literals would be undetectable typos at compile time.
- **After:** All names centralised as typed Go constants. Typos are compile errors. Consistent with the existing pattern for all other indices (`TransactionsIndex`, `BlockIndex`, etc.).

### 1.5 Failure & Risk Analysis

- **Failure Modes:** Fresh deployment will not create DRWA indices or apply ILM policies. All DRWA bulk writes fail with `index_not_found_exception` — or silently succeed with wrong mappings if ES `auto_create_index` is enabled.
- **Silent Failure Risk:** High — if ES auto-creates indices, data is written with dynamic mappings (wrong field types, no ILM policy, no aliases).
- **Risk Level:** High

### 1.6 Test Analysis

- No test verifies that all constants in `constants.go` have a corresponding entry in the `indexes` slice. No integration test verifies all expected indices exist after startup.

### 1.7 Cross-System Impact

- `elasticProcessor.go` already references the 4 DRWA index constants in `indexDRWA*` methods — these compile correctly. The runtime failure only occurs because the indices are never created on startup.
- `MrvProofsIndex` and `MrvProofsPolicy` are not referenced anywhere outside `constants.go`.

### 1.8 Final Decision

**Status: 🔴 HOLD**

Three required fixes before approval:
1. Add 4 DRWA index constants to the `indexes` slice in `elasticProcessor.go`.
2. Add 4 DRWA policy constants to the `indexesPolicies` slice in `createIndexPolicies()`.
3. Either wire `MrvProofsIndex`/`MrvProofsPolicy` into startup or move them to the MRV branch to avoid dead code in main.

---

## 2. `data/drwa.go`

### 2.1 Change Scope

- **Files Changed:** `data/drwa.go`
- **Change Type:** Feature (New File)
- **New stored state:** Yes — 4 structs define the schema for 4 new Elasticsearch indices.

5 new structs:
```go
DRWAEventMaterialization       // Internal metadata for event extraction
DrwaDenialRecord               // drwa-denials index
DrwaHolderComplianceRecord     // drwa-holder-compliance index
DrwaAttestationRecord          // drwa-attestations index
DrwaTokenPolicyRecord          // drwa-token-policies index
```

### 2.2 Impacted System Flow

- **Flow:** DRWA Event Schema Definition → JSON Serialization → Elasticsearch Document Structure
- **Entry Point:** `drwaEventsProcessor.buildXxxRecord()` — constructs instances from raw event topics
- **Exit Point:** `json.Marshal()` in `elasticProcessor.indexDRWA*()` — serializes to JSON for ES bulk write
- **Key detail:** `omitempty` on boolean fields causes conditional serialization. When a boolean is `false`, the field is omitted from JSON output, creating a stale state bug in ES when a field transitions `true → false`.

### 2.3 Invariant Analysis

- **Are invariants affected?** Yes
- **Invariant (DRWA Golden Rule #3 — Consistency):** The shard-local shadow state must always match the Registry Contract state. This repo is the ES observability layer — its documents must reflect current on-chain state with zero drift. If a compliance flag changes `true → false` on-chain, the ES document must update to `false`.
- **Violation — Sync Drift via `omitempty`:** 7 boolean fields across 3 structs have `omitempty`. When a boolean transitions `true → false` on-chain, the field is silently omitted from JSON — ES retains the old `true` value indefinitely. This is the ES equivalent of the DRWA sync drift failure scenario: a blacklisted holder's `transferLocked` flips to `false` on-chain but ES still shows `true`, causing compliance queries to return wrong results.
  - `DrwaHolderComplianceRecord`: `TransferLocked`, `ReceiveLocked`, `AuditorAuthorized`
  - `DrwaAttestationRecord`: `Approved`
  - `DrwaTokenPolicyRecord`: `Regulated`, `GlobalPause`, `StrictAuditorMode`

  Example failure:
  ```
  Block 100: GlobalPause = true  → ES: {"globalPause": true}
  Block 200: GlobalPause = false → JSON: {} (field omitted)
                                 → ES: {"globalPause": true} (unchanged — sync drift)
  ```

### 2.4 Change Explanation

- **Before:** No DRWA record types. Events stored only as raw hex topics in generic `logs`/`events` indices.
- **After:** 4 new ES indices have explicit schemas. Downstream consumers can query structured DRWA data.

### 2.5 Failure & Risk Analysis

- **Stale boolean state (High):** Compliance flags that change `true → false` remain `true` in ES indefinitely. Silent — no error raised.
- **Schema drift:** Consumers expecting `"globalPause": false` get `undefined` when field is omitted. Breaks aggregations and filters.
- **All booleans false edge case:** `DrwaTokenPolicyRecord` with all flags false produces JSON with no policy flags — indistinguishable from "flags never set."
- **Risk Level:** Medium-High

### 2.6 Test Analysis

- No unit tests for these structs. No test verifies `false` boolean values are omitted. No integration test verifies `true → false` transition correctly updates ES.

### 2.7 Cross-System Impact

- ES index mappings must define boolean fields as `type: boolean`. If auto-generated from first document that omits all booleans, ES won't know those fields exist.
- Removing `omitempty` from booleans is a bug fix, not a breaking change.

### 2.8 Final Decision

**Status: 🔴 HOLD**

Required fix — remove `omitempty` from all 7 boolean fields:
```go
// DrwaHolderComplianceRecord
TransferLocked    bool `json:"transferLocked"`
ReceiveLocked     bool `json:"receiveLocked"`
AuditorAuthorized bool `json:"auditorAuthorized"`
// DrwaAttestationRecord
Approved bool `json:"approved"`
// DrwaTokenPolicyRecord
Regulated         bool `json:"regulated"`
GlobalPause       bool `json:"globalPause"`
StrictAuditorMode bool `json:"strictAuditorMode"`
```

---

## 3. `data/drwa_test.go`

### 3.1 Change Scope

- **Files Changed:** `data/drwa_test.go`
- **Change Type:** Feature (New File — Test Suite)
- **New stored state:** No.

5 new test functions:
```go
TestDRWAEventMaterialization_JSONRoundTrip
TestDrwaDenialRecord_JSONFieldNames
TestDrwaHolderComplianceRecord_JSONRoundTrip
TestDrwaAttestationRecord_JSONRoundTrip
TestDrwaTokenPolicyRecord_JSONRoundTrip
```

### 3.2 Impacted System Flow

- **Flow:** Unit Test Execution → JSON Serialization Validation
- **Key detail:** `TestDrwaDenialRecord_JSONFieldNames` unmarshals JSON into `map[string]any` to verify field names — the only test that checks actual JSON keys. All other tests use round-trip which does not validate field presence.

### 3.3 Invariant Analysis

- **Are invariants affected?** Partially
- Tests correctly validate round-trip serialization and field name stability. However they **fail to detect the `omitempty` boolean bug**:
  ```go
  record := DrwaHolderComplianceRecord{
      TransferLocked: false,  // omitempty → omitted from JSON
  }
  // Marshal → Unmarshal → decoded.TransferLocked = false (Go zero value)
  // require.Equal(record, decoded) → PASS ✓
  // Test passes despite field being absent from JSON
  ```

### 3.4 Change Explanation

- **Before:** No tests for DRWA structs.
- **After:** Basic coverage for JSON serialization. Prevents field name regressions.

### 3.5 Failure & Risk Analysis

- **False sense of security:** All tests pass but `omitempty` boolean bug is not detected.
- **Round-trip masking:** The round-trip pattern hides serialization bugs where fields are omitted but restored to zero values during unmarshaling.
- **Risk Level:** Medium (for coverage gaps, not for the test code itself)

### 3.6 Test Analysis

- 100% struct coverage, ~60% edge case coverage.
- Missing: `omitempty` boolean behavior, stale state scenario, all-false booleans, field presence in JSON for non-denial structs.

### 3.7 Cross-System Impact

- Test-only. No production impact.

### 3.8 Final Decision

**Status: 🟡 APPROVE with recommendations**

Tests are correct for what they validate. Recommended follow-up:
1. Add tests that expose the `omitempty` boolean bug (assert fields are absent when `false`).
2. After fixing `omitempty` in `drwa.go`, update tests to assert fields are always present.

---

## 4. `data/tokens.go`

### 4.1 Change Scope

- **Files Changed:** `data/tokens.go`
- **Change Type:** Feature
- **New stored state:** Yes — adds a `drwa` nested sub-object to existing `tokens` ES index documents.

Two additions:
```go
// New struct
type DrwaTokenInfo struct {
    Regulated          bool   `json:"regulated,omitempty"`
    PolicyID           string `json:"policyId,omitempty"`
    TokenPolicyVersion uint64 `json:"tokenPolicyVersion,omitempty"`
    GlobalPause        bool   `json:"globalPause,omitempty"`
    StrictAuditorMode  bool   `json:"strictAuditorMode,omitempty"`
}

// New fields on TokenInfo
Drwa       *DrwaTokenInfo `json:"drwa,omitempty"`
DrwaUpdate bool           `json:"-"`
```

### 4.2 Impacted System Flow

- **Flow:** DRWA Event → Token Document Update in Elasticsearch
- **Entry Point:** `drwaEventsProcessor.tryBuildTokenInfo()` — builds `TokenInfo` with `Drwa` populated and `DrwaUpdate: true`
- **Exit Point:** `serializeTokenDrwa()` — issues Painless `putAll` script update to `tokens` ES index
- **Key detail:** `DrwaUpdate: true` acts as a routing signal. `serializeToken()` checks this flag first and routes to `serializeTokenDrwa()` which performs a partial merge — preserving all non-DRWA fields.

### 4.3 Invariant Analysis

- **Are invariants affected?** Yes
- **Invariant 1:** DRWA update must not overwrite non-DRWA fields — satisfied by `putAll` partial merge.
- **Invariant 2:** `DrwaUpdate: true` must only be set when `Drwa` is non-nil — currently enforced by `tryBuildTokenInfo` always setting both together, but no guard in `serializeTokenDrwa`.
- **Violation:** All 5 fields in `DrwaTokenInfo` have `omitempty`. `GlobalPause: false`, `Regulated: false`, `StrictAuditorMode: false`, and `TokenPolicyVersion: 0` are all silently omitted from JSON. `putAll` will not reset them in ES — old values persist. This is a **DRWA Golden Rule #3 (Consistency) violation** — the ES `tokens` index drifts from on-chain policy state, identical in nature to the sync drift failure scenario defined in the domain brief.

### 4.4 Change Explanation

- **Before:** `tokens` index had no DRWA compliance state. A regulated token was indistinguishable from a non-regulated one.
- **After:** Token documents carry a `drwa` sub-object with materialized current compliance policy state — a single-document lookup gives the full picture without replaying history.

### 4.5 Failure & Risk Analysis

- **`Drwa` nil + `DrwaUpdate: true`:** `json.Marshal(nil)` returns `null`. Painless `putAll` on null throws NullPointerException in ES — hard failure, aborts block indexing.
- **`omitempty` stale state:** `GlobalPause: false` after `GlobalPause: true` leaves ES showing `globalPause: true` indefinitely. Silent.
- **`TokenPolicyVersion: 0`:** Version 0 omitted from JSON — old version number persists in ES.
- **Upsert creates incomplete document:** If token doesn't exist in ES yet, upsert creates `{identifier, token, drwa}` only — missing all other token metadata until a full token event is processed.
- **Risk Level:** Medium

### 4.6 Test Analysis

- No test covers `GlobalPause: false → putAll` omission. No test covers nil `Drwa` with `DrwaUpdate: true`. No test covers the upsert path.

### 4.7 Cross-System Impact

- `drwa` sub-object is additive — existing consumers unaffected.
- ES `tokens` index mapping must be updated to define `drwa` as an `object` type. Without explicit mapping, auto-mapping on first write may produce inconsistent field types.

### 4.8 Final Decision

**Status: 🔴 HOLD**

Required fixes:
1. Remove `omitempty` from all boolean fields in `DrwaTokenInfo` (`Regulated`, `GlobalPause`, `StrictAuditorMode`).
2. Add nil guard in `serializeTokenDrwa` for `tokenData.Drwa`.
3. Confirm `tokens` ES index template includes explicit mapping for the `drwa` object.

---

## 5. `data/mrv.go`

### 5.1 Change Scope

- **Files Changed:** `data/mrv.go`
- **Change Type:** Feature (New File)
- **New stored state:** Yes — defines schema for `mrv-proofs` Elasticsearch index.

1 new struct:
```go
MRVProofMaterialization  // Proof extraction metadata for carbon credit verification
```

T-41 update added 4 fields to align with `mx-api-service` `MrvProofDocument` entity: `PublicProjectID`, `EvidenceManifestHash`, `IndexedAt`, `SourceEventName`.

### 5.2 Impacted System Flow

- **Flow:** MRV Proof Anchoring → Elasticsearch Indexing → API Service Consumption
- **Entry Point:** On-chain `Registry` contract emits proof anchoring event → MRV event processor (not found in scanned files)
- **Exit Point:** `mx-api-service` queries `mrv-proofs` ES index
- **Key detail:** 15 of 16 fields have `omitempty` — nearly all fields are optional in JSON output, creating ambiguity about which are truly required.

### 5.3 Invariant Analysis

- **Are invariants affected?** Yes
- **Evidence Binding (MRV Golden Rule #2):** Every carbon credit token must be linked to an immutable `reportHash`. `ReportHash` has `omitempty` — a proof record without a report hash can be written to ES, violating this rule.
- **No Double Issuance (MRV Golden Rule #1):** A single `ReportID` can only appear once. No deduplication mechanism exists in the struct or serializer. Concrete fix: use `ReportID` as the ES document `_id` — ES enforces uniqueness at the index level for free, making a second write with the same `ReportID` an idempotent overwrite rather than a silent duplicate.
- **Buffer Integrity (MRV Golden Rule #3):** Credits cannot be issued without a mandatory buffer deduction (10–15%) sent to the buffer-pool contract. `MRVProofMaterialization` has no field tracking buffer deduction status (`bufferDeducted bool`, `bufferPct`, or `netCredits`). If a proof is indexed without buffer deduction confirmation, the ES audit trail cannot prove Golden Rule #3 was satisfied for that credit batch.
- **8-Gate Verification (G1–G8):** The MRV domain brief defines 8 institutional gates that must pass before issuance (G1: Methodology, G2: Boundaries, G4: Science, etc.). `MRVProofMaterialization` has only `ProofStatus string` — no gate-level fields (`g1Pass`, `g2Pass`, etc.). The struct cannot represent which gates passed or failed, making it impossible to query ES for proofs that failed a specific gate. This is a schema gap.
- **Proof Status Lifecycle:** `ProofStatus` has `omitempty` — a proof with no status is indistinguishable from one with status `""`.

### 5.4 Change Explanation

- **Before:** No MRV proof indexing. Carbon credit verification history not queryable.
- **After:** `mrv-proofs` ES index provides structured, queryable audit trail for carbon credit verification.

### 5.5 Failure & Risk Analysis

- **Missing ReportHash (Critical):** Proof record with `ReportID` but no `ReportHash` violates Evidence Binding (Golden Rule #2). Carbon credits linked to this proof have no verifiable evidence.
- **Duplicate ReportID (Critical):** Same `ReportID` indexed twice — no deduplication. Cannot determine canonical proof. Fix: use `ReportID` as ES document `_id`.
- **Buffer deduction not tracked (Critical):** No field in `MRVProofMaterialization` confirms buffer deduction occurred. ES audit trail cannot prove Golden Rule #3 compliance for any credit batch.
- **8-Gate result not captured (High):** `ProofStatus` is a single string — cannot represent which of G1–G8 passed or failed. A proof that failed G4 (Science) is indistinguishable from one that passed all gates if `ProofStatus` is the same string.
- **Invalid ProofStatus (Medium):** Proof with `ProofStatus=""` breaks lifecycle queries.
- **Timestamp ambiguity (Low):** 4 timestamp fields (`AnchoredAt`, `IndexedAt`, `Timestamp`, `TimestampMs`) with no comments explaining their difference.
- **No MRV event processor found** — struct is defined but no code constructs `MRVProofMaterialization` instances from on-chain events. Pipeline may be incomplete.
- **Risk Level:** High

### 5.6 Test Analysis

- No test file for `data/mrv.go`. Unlike DRWA, MRV has zero test coverage. No test verifies JSON field names match `mx-api-service` expectations.

### 5.7 Cross-System Impact

- `mx-api-service` expects `MrvProofDocument` entity with exact field names. Mismatch causes API queries to fail or return incomplete data.
- `mrv-proofs` index constant defined in `constants.go` but not wired into startup `indexes` slice — index never created on fresh deployment.

### 5.8 Final Decision

**Status: 🔴 HOLD**

Required fixes:
1. Remove `omitempty` from `ReportHash`, `ProofStatus`, `AnchoredAt`, `IndexedAt`.
2. Use `ReportID` as the ES document `_id` in the MRV serializer — enforces No Double Issuance (Golden Rule #1) at the ES layer.
3. Add `BufferDeducted bool` and `BufferPct uint64` fields to `MRVProofMaterialization` to satisfy Buffer Integrity (Golden Rule #3) in the audit trail.
4. Add gate-level result fields (`G1Pass`, `G2Pass`, `G4Pass` etc.) or a `GateResults map[string]bool` to capture 8-Gate verification outcomes per proof.
5. Add `MrvProofsIndex` to `indexes` slice in `elasticProcessor.go`.
6. Verify MRV event processor exists and constructs `MRVProofMaterialization` instances.
7. Add unit tests (JSON field names, omitempty behavior, round-trip).
8. Add comments documenting timestamp field semantics.

---

## 6. `data/logs.go`

### 6.1 Change Scope

- **Files Changed:** `data/logs.go`
- **Change Type:** Feature
- **New stored state:** Yes — 4 new fields on `PreparedLogsResults` carry records that get written to 4 new ES indices.

```go
DrwaDenials          []*DrwaDenialRecord
DrwaHolderCompliance []*DrwaHolderComplianceRecord
DrwaAttestations     []*DrwaAttestationRecord
DrwaTokenPolicies    []*DrwaTokenPolicyRecord
```

### 6.2 Impacted System Flow

- **Flow:** Block Log Processing → Elasticsearch Indexing
- **Entry Point:** `logsAndEventsProcessor.ExtractDataFromLogs()` — receives raw on-chain log events
- **Exit Point:** `elasticProcessor.indexDRWA*()` — writes serialized records to ES via bulk request
- **Key detail:** `PreparedLogsResults` is the single handoff point between the parsing layer and the indexing layer. All parsed DRWA data must flow through it.

### 6.3 Invariant Analysis

- **Are invariants affected?** Yes — and previously broken.
- **Invariant:** Every record accumulated into `logsData` during event processing must be forwarded in `PreparedLogsResults`.
- Three of four fields (`DrwaDenials`, `DrwaHolderCompliance`, `DrwaAttestations`) correctly flow end-to-end. `DrwaTokenPolicies` was previously missing from the `ExtractDataFromLogs` return — token policy records were parsed and silently discarded. This is fixed in `logsAndEventsProcessor.go`.

### 6.4 Change Explanation

- **Before:** Indexer had no awareness of DRWA events. All `drwa*` events stored only as raw log entries.
- **After:** 4 dedicated ES indices receive structured DRWA records. Compliance queries are now possible.

### 6.5 Failure & Risk Analysis

- **Silent data loss (previously):** `DrwaTokenPolicies` was parsed but never forwarded — fixed in `logsAndEventsProcessor.go`.
- **Malformed events:** If an event emits fewer topics than the builder expects, the builder returns `nil` and the record is silently skipped with no log.
- **ES unavailable:** If ES is down when a block with DRWA events is processed, records are permanently lost — no retry queue.
- **Mass compliance update:** A block with thousands of DRWA events produces a very large slice — no cap exists. `BufferSlice` handles chunking.
- **Risk Level:** Medium

### 6.6 Test Analysis

- No integration test processes a block containing all 4 DRWA event types and asserts all 4 slices in `PreparedLogsResults` are non-empty. This test would have caught the original `DrwaTokenPolicies` pipeline bug.

### 6.7 Cross-System Impact

- Any consumer querying `drwa-token-policies` ES index will get empty results until the pipeline bug fix in `logsAndEventsProcessor.go` is deployed.
- All 4 new ES indices are not added to the `indexes` slice in `elasticProcessor.go` — never created on startup (cross-cutting blocker #2).

### 6.8 Final Decision

**Status: 🔴 HOLD**

Required fixes:
1. Confirm `DrwaTokenPolicies: lgData.drwaTokenPolicies` is present in `ExtractDataFromLogs` return (fixed in `logsAndEventsProcessor.go` — both must be deployed together).
2. Add all 4 DRWA index constants to the `indexes` slice in `elasticProcessor.go`.

---

## 7. `process/elasticproc/logsevents/logsData.go`

### 7.1 Change Scope

- **Files Changed:** `process/elasticproc/logsevents/logsData.go`
- **Change Type:** Feature
- **New stored state:** No — `logsData` is a block-scoped accumulator, discarded after `ExtractDataFromLogs()` returns.

4 new fields added to `logsData` struct and initialised in `newLogsData()`:
```go
drwaDenials          []*data.DrwaDenialRecord
drwaHolderCompliance []*data.DrwaHolderComplianceRecord
drwaAttestations     []*data.DrwaAttestationRecord
drwaTokenPolicies    []*data.DrwaTokenPolicyRecord
```

All initialised with `make([]*data.XxxRecord, 0)` — not nil.

### 7.2 Impacted System Flow

- **Flow:** Per-Block Accumulator Lifecycle
- **Entry Point:** `newLogsData()` — called once per block
- **Exit Point:** `collectEventResults()` appends into these slices; `ExtractDataFromLogs()` reads them into `PreparedLogsResults`
- **Lifecycle:** `make` → `append` (N times) → `read once` → `discard`. No concurrent access.

### 7.3 Invariant Analysis

- **Are invariants affected?** Yes — correctly satisfied.
- Every slice field must be initialised in `newLogsData()` — all 4 are. Every field must be forwarded in `ExtractDataFromLogs()` — confirmed in `logsAndEventsProcessor.go`.
- `make([]*data.XxxRecord, 0)` preferred over nil: produces `[]` not `null` in JSON if ever marshalled.

### 7.4 Change Explanation

- **Before:** No DRWA fields in `logsData`. Even if `drwaEventsProcessor` had been registered, there was nowhere to hold records between the event loop and the return.
- **After:** `logsData` is the complete per-block accumulator for all indexable data including DRWA.

### 7.5 Failure & Risk Analysis

- **nil slice:** `append` on nil slice in Go allocates a new backing array — no panic. But `make(..., 0)` is still preferred for JSON marshalling consistency.
- **Empty block:** Zero DRWA events → all 4 slices remain empty `[]` → `len(records) == 0` guard in `elasticProcessor.indexDRWA*()` correctly skips ES write.
- **Risk Level:** Low — pure data structure change, no logic, no concurrency.

### 7.6 Test Analysis

- No test verifies `newLogsData()` initialises all 4 fields as non-nil. A simple unit test asserting `ld.drwaDenials != nil` would catch future regressions.

### 7.7 Cross-System Impact

- `logsData` is package-private — zero external impact. Only used within the `logsevents` package.

### 7.8 Final Decision

**Status: 🟢 APPROVE**

Simplest change in the feature. Correct, consistent, no logic, no risk.

---

## 8. `process/elasticproc/logsevents/interface.go`

### 8.1 Change Scope

- **Files Changed:** `process/elasticproc/logsevents/interface.go`
- **Change Type:** Feature
- **New stored state:** No — `argOutputProcessEvent` is a short-lived value type per event.

4 new fields added to `argOutputProcessEvent`:
```go
drwaDenial           *data.DrwaDenialRecord
drwaHolderCompliance *data.DrwaHolderComplianceRecord
drwaAttestation      *data.DrwaAttestationRecord
drwaTokenPolicy      *data.DrwaTokenPolicyRecord
```

### 8.2 Impacted System Flow

- **Flow:** Single Event Processing → Result Accumulation
- **Entry Point:** `eventsProcessor.processEvent()` — each processor returns an `argOutputProcessEvent`
- **Exit Point:** `logsAndEventsProcessor.collectEventResults()` — nil-checks each field and appends non-nil values into `logsData`
- **Key detail:** All 4 new fields are pointer types — `nil` correctly represents "this event produced no record of this type." Non-DRWA processors return zero values (nil pointers) for the new fields automatically.

### 8.3 Invariant Analysis

- **Are invariants affected?** Yes — correctly.
- All 4 new fields are pointer types, consistent with existing fields. `processed bool` remains last. `collectEventResults` correctly nil-checks each new field before appending.

### 8.4 Change Explanation

- **Before:** No way for any `eventsProcessor` to return DRWA records — nowhere to put them in the return value.
- **After:** Any processor can return up to 4 DRWA records alongside existing outputs. Existing processors require no changes — Go zero-initialises unset pointer fields to nil.

### 8.5 Failure & Risk Analysis

- **Struct size:** Adding 4 pointer fields increases struct size by 32 bytes (4 × 8-byte pointers on 64-bit). Negligible but worth noting for high-throughput blocks.
- **Risk Level:** Low — pure struct extension, no behavioural change for existing processors.

### 8.6 Test Analysis

- No test verifies non-DRWA processors return zero values for the 4 new fields. No test verifies `collectEventResults` accumulates all 4 fields correctly when all are non-nil simultaneously.

### 8.7 Cross-System Impact

- `argOutputProcessEvent` is package-private — zero external impact. All existing `eventsProcessor` implementations compile without changes.

### 8.8 Final Decision

**Status: 🟢 APPROVE**

Minimal, correct, well-scoped struct extension. Prerequisite for `drwaEventsProcessor` to function.

---

## 9. `process/elasticproc/logsevents/drwaEventsProcessor.go`

### 9.1 Change Scope

- **Files Changed:** `process/elasticproc/logsevents/drwaEventsProcessor.go`
- **Change Type:** Feature (New File)
- **New stored state:** Yes — this is the only code path that populates the 4 DRWA ES indices.

12 event constants defined. 5 builder methods:
- `tryBuildTokenInfo()` — materializes token policy state for `tokens` index
- `tryBuildTokenPolicyRecord()` — policy history for `drwa-token-policies`
- `tryBuildDenialRecord()` — transfer denials for `drwa-denials`
- `tryBuildHolderComplianceRecord()` — KYC/AML updates for `drwa-holder-compliance`
- `tryBuildAttestationRecord()` — auditor attestations for `drwa-attestations`

### 9.2 Impacted System Flow

- **Flow:** On-Chain DRWA Event → Topic Parsing → ES Index Write
- **Entry Point:** `logsAndEventsProcessor.ExtractDataFromLogs()` calls `drwaEventsProcessor.processEvent()` for every log event
- **Exit Point:** Parsed records returned to `logsData` → `elasticProcessor.indexDRWA*()` → ES bulk write
- **Key detail:** `tryBuildHolderComplianceRecord()` uses progressive topic parsing with 11 conditional checks (`if len(topics) >= N`). Allows variable-length events but creates ambiguity — a record with only 2 topics is valid but has no KYC/AML data.

### 9.3 Invariant Analysis

- **Are invariants affected?** Yes — several issues:

  **Issue 1: 4 events defined but not handled**
  - `drwaTransferAllowedEvent`, `drwaMetadataProtectionEvent`, `drwaGovernanceProposedEvent`, `drwaGovernanceAcceptedEvent` — defined but never parsed. Audit trail incomplete.
  - Note: `drwaAuditorProposedEvent` and `drwaAuditorAcceptedEvent` ARE handled — `tryBuildAttestationRecord()` processes both and produces `DrwaAttestationRecord` entries.

  **Issue 2: Topic index skip in `drwaAttestationRecordedEvent`**
  ```go
  record.Approved = bytesToBool(topics[4])  // topics[3] is never read
  ```
  Either topic[3] contains data that should be parsed (missing field) or it is unused (off-by-one). Cannot determine without smart contract source.

  **Issue 3: Progressive parsing creates incomplete records**
  - `tryBuildHolderComplianceRecord()` with only 2 topics returns a valid record with no KYC/AML data. Downstream queries filtering on `kycStatus` will miss this record.

  **Issue 4: No denial code validation**
  - `tryBuildDenialRecord()` accepts any string as `DenialCode`. DRWA domain brief specifies 12 valid codes (0-11). Code "999" is accepted without error.
  - **Code 0 Priority (DRWA Golden Rule #4):** The domain brief states that if a token is DRWA-enabled but has no synced policy, Code 0 (`PolicyNotSynced`) must block all transfers — it is the highest-priority denial code. The indexer has no special handling or validation for Code 0. If a Code 0 denial event is emitted and indexed with a malformed or missing code string, the compliance audit trail for the most critical failure mode is silently corrupted.

### 9.4 Change Explanation

- **Before:** No DRWA event parsing. All `drwa*` events ignored or stored as raw hex topics.
- **After:** 8 of 12 DRWA events parsed into structured records (`drwaAssetRegisteredEvent`, `drwaTokenPolicyEvent`, `drwaGlobalPauseEvent`, `drwaHolderComplianceEvent`, `drwaTransferDeniedEvent`, `drwaAuditorProposedEvent`, `drwaAuditorAcceptedEvent`, `drwaAttestationRecordedEvent`). Compliance officers can query transfer denials, KYC updates, and policy changes directly.

### 9.5 Failure & Risk Analysis

- **Silent event loss (High):** 4 defined events never parsed (`drwaTransferAllowedEvent`, `drwaMetadataProtectionEvent`, `drwaGovernanceProposedEvent`, `drwaGovernanceAcceptedEvent`). Governance audit trail completely missing.
- **Topic index bug (Medium):** topic[3] skipped in attestation — potential permanent data loss.
- **Incomplete compliance records (Medium):** 2-topic holder compliance records have no KYC/AML data.
- **Invalid denial codes (Low):** Smart contract bug emitting code "999" accepted silently.
- **Multiple events per TX:** If a transaction emits `drwaAssetRegistered` + `drwaTokenPolicy`, only the last `TokenInfo` is returned — earlier overwritten.
- **Risk Level:** Medium-High

### 9.6 Test Analysis

- Zero test coverage for topic parsing logic at time of initial audit. `drwaEventsProcessor_test.go` was added subsequently (see File 10).

### 9.7 Cross-System Impact

- VM Enforcement Gate (`go-core`): This processor creates the ES audit trail proving VM denials happened. Missing denial records = invisible compliance failures.
- Policy Registry Contract (Rust): Emits `drwaTokenPolicy` events. If parsing fails, ES and on-chain state diverge (violates DRWA Golden Rule #3).
- Governance Tools: Emit `drwaGovernanceProposed/Accepted` events — not handled. Governance audit trail completely missing.

### 9.8 Final Decision

**Status: 🔴 HOLD**

Required fixes:
1. Add handlers for 4 missing events (`drwaTransferAllowedEvent`, `drwaMetadataProtectionEvent`, `drwaGovernanceProposedEvent`, `drwaGovernanceAcceptedEvent`) or document why they are intentionally not indexed.
2. Fix or document topic[3] skip in `drwaAttestationRecordedEvent`.
3. Add denial code validation (0-11 range per DRWA domain brief).
4. Add unit tests (see File 10).
5. Add validation for empty required topics (TokenID, Holder, DenialCode).

---

## 10. `process/elasticproc/logsevents/drwaEventsProcessor_test.go`

### 10.1 Change Scope

- **Files Changed:** `process/elasticproc/logsevents/drwaEventsProcessor_test.go`
- **Change Type:** Feature (New File — Unit Tests)
- **New stored state:** No.

5 test functions:
```go
TestDRWAEventsProcessorMarksTransaction
TestDRWAEventsProcessorBuildsTokenInfoForAssetRegistration
TestDRWAEventsProcessorBuildsTokenInfoForTokenPolicy
TestDRWAEventsProcessorBuildsHolderComplianceRecord
TestDRWAEventsProcessorBuildsAttestationRecord
```

### 10.2 Impacted System Flow

- **Flow:** Unit Test Execution → Validation of Event Parsing Logic
- **Key detail:** Tests use `[]byte("true")` / `[]byte("false")` as boolean topics instead of `{0x01}` / `{0x00}`. Tests pass — meaning `bytesToBool()` accepts string input (reads first byte: 't' = 0x74 ≠ 0x00 → true). This may or may not match production event format.

### 10.3 Invariant Analysis

- **Are invariants affected?** Partially

  **Issue 1: Boolean topics use string format**
  - Tests pass with `[]byte("true")` — `bytesToBool` is lenient. But if production events use byte format `{0x01}`, tests validate wrong behavior.

  **Issue 2: Topic[3] in attestation test confirms it is provided but not parsed**
  ```go
  Topics: [][]byte{
      []byte("HOTEL-1234"),  // [0] TokenID
      []byte("erd1subject"), // [1] Subject
      []byte("erd1auditor"), // [2] Auditor
      []byte("kyc"),         // [3] ??? — provided but parser skips it
      []byte("true"),        // [4] Approved
      {7},                   // [5] AttestedRound
  }
  ```
  Test provides topic[3] = "kyc" but does not assert it is parsed — confirms the bug in `drwaEventsProcessor.go`.

  **Issue 3: 3 handled events not tested**
  - `drwaGlobalPauseEvent`, `drwaAuditorProposedEvent`, `drwaAuditorAcceptedEvent` — all three are handled in production code but have no corresponding test.

  **Issue 4: `drwaTransferDeniedEvent` parsing never tested**
  - `TestDRWAEventsProcessorMarksTransaction` uses this event but provides no topics. `tryBuildDenialRecord()` is never tested — most critical event for compliance.

### 10.4 Change Explanation

- **Before:** Zero test coverage for `drwaEventsProcessor`.
- **After:** 50% coverage (4 of 8 handled events tested with meaningful topic assertions: `drwaAssetRegisteredEvent`, `drwaTokenPolicyEvent`, `drwaHolderComplianceEvent`, `drwaAttestationRecordedEvent`). `TestDRWAEventsProcessorMarksTransaction` uses `drwaTransferDeniedEvent` but provides no topics — `tryBuildDenialRecord()` returns nil, so denial parsing is not exercised. Regression prevention for core parsing logic.

### 10.5 Failure & Risk Analysis

- **Missing denial test (High):** `tryBuildDenialRecord()` never tested. Most critical event for compliance.
- **String boolean format (Medium):** Tests may not match production data format.
- **Incomplete coverage (Medium):** 3 handled events untested.
- **Risk Level:** Medium

### 10.6 Test Analysis

- Covered: `drwaAssetRegisteredEvent`, `drwaTokenPolicyEvent`, `drwaHolderComplianceEvent`, `drwaAttestationRecordedEvent`, transaction marking.
- Missing: `drwaTransferDeniedEvent` parsing, `drwaGlobalPauseEvent`, `drwaAuditorProposedEvent`, `drwaAuditorAcceptedEvent`, progressive parsing (2-topic minimal), invalid input.

### 10.7 Cross-System Impact

- Test-only. No production impact.

### 10.8 Final Decision

**Status: 🟡 APPROVE with recommendations**

62.5% coverage is better than 0%. Tests are well-structured and use `t.Parallel()`. Critical gap: add denial record test immediately.

Required additions:
1. Add `TestDRWAEventsProcessorBuildsDenialRecord` — most critical missing test.
2. Add tests for `drwaGlobalPauseEvent`, `drwaAuditorProposedEvent`, `drwaAuditorAcceptedEvent`.
3. Add progressive parsing test for `drwaHolderComplianceEvent` with 2 topics (minimal).
4. Document topic[3] skip in attestation test with a comment.

---

## 11. `process/elasticproc/logsevents/drwaEventsProcessor_benchmark_test.go`

### 11.1 Change Scope

- **Files Changed:** `process/elasticproc/logsevents/drwaEventsProcessor_benchmark_test.go`
- **Change Type:** Feature (New File — Benchmark)
- **New stored state:** No.

1 benchmark function: `BenchmarkDRWAEventsProcessor_ProcessPolicyEvent`

### 11.2 Impacted System Flow

- **Flow:** Performance Measurement → Optimization Guidance
- **Key detail:** Boolean topics use string format (`[]byte("true")`) instead of byte format (`{0x01}`). Benchmark measures performance of parsing wrong data format — results are misleading.

### 11.3 Invariant Analysis

- **Are invariants affected?** Yes
- **Performance Baseline:** DRWA domain brief emphasizes "Is the gate cheap?" Benchmarks must use realistic data. String boolean format is not production format.
- Only 1 of 8 event types benchmarked. `drwaHolderComplianceEvent` (11 topics, most complex) and `drwaTransferDeniedEvent` (most common) are not benchmarked.

### 11.4 Change Explanation

- **Before:** No performance benchmarks for DRWA event processing.
- **After:** Baseline metrics for `drwaTokenPolicyEvent`. Enables regression detection in CI.

### 11.5 Failure & Risk Analysis

- **Invalid test data (High):** Boolean topics use string format. Benchmark measures wrong data — optimizations based on results may not improve real-world performance.
- **Incomplete coverage (Medium):** Only 1 event type. Cannot identify real bottleneck.
- **Risk Level:** Medium

### 11.6 Test Analysis

- 12.5% coverage (1 of 8 event types). Missing: `drwaHolderComplianceEvent` (most complex), `drwaTransferDeniedEvent` (most common), multiple events per transaction.

### 11.7 Cross-System Impact

- Benchmark-only. No production impact.

### 11.8 Final Decision

**Status: 🟡 APPROVE with recommendations**

Having benchmarks is better than none. Easy to fix.

Required fixes:
1. Change string booleans to byte format: `{0x01}` for true, `{0x00}` for false.
2. Add `timestamp` and `timestampMs` fields to `argsProcessEvent`.
3. Add benchmarks for `drwaHolderComplianceEvent` and `drwaTransferDeniedEvent`.

---

## 12. `process/elasticproc/logsevents/logsAndEventsProcessor.go`

### 12.1 Change Scope

- **Files Changed:** `process/elasticproc/logsevents/logsAndEventsProcessor.go`
- **Change Type:** Feature + Refactor
- **New stored state:** Yes — DRWA forwarding in `ExtractDataFromLogs` is what makes DRWA records reach Elasticsearch.

Three changes:
1. `drwaProc` registered in `createEventsProcessors` (second in list, after `scDeploysProc`)
2. All 4 DRWA slices forwarded in `ExtractDataFromLogs` return
3. Inline result handling extracted into new `collectEventResults` method

### 12.2 Impacted System Flow

- **Flow:** Block Log Processing → `PreparedLogsResults` → Elasticsearch
- **Entry Point:** `ExtractDataFromLogs()` — called once per block
- **Exit Point:** `PreparedLogsResults` returned to `elasticProcessor.SaveTransactions()`
- **Key detail:** `drwaProc` is second in `eventsProcs`. The `processEvent` loop calls `return` on `res.processed == true` only when the event hash is NOT found in `txsMap` or `scrsMap`. For events belonging to a tx or scr, the inner processor loop `continue`s to the next **processor** (not the next event) — meaning subsequent processors still run for that event. However, since `drwa*` prefixed events are not matched by any other processor, this has no practical effect on correctness.

### 12.3 Invariant Analysis

- **Are invariants affected?** Yes — this change **fixes** a previously broken invariant.
- Before: `DrwaDenials`, `DrwaHolderCompliance`, `DrwaAttestations`, `DrwaTokenPolicies` all missing from `ExtractDataFromLogs` return — all DRWA data silently discarded.
- After: All 4 slices forwarded. `collectEventResults` handles all 7 fields of `argOutputProcessEvent` — none missed.
- Processor ordering: `scDeploysProc` handles `SCDeploy`/`SCUpgrade` events — never have `drwa` prefix. No conflict.

### 12.4 Change Explanation

- **Before:** `drwaEventsProcessor` never instantiated. Even if it had been, results would have been lost — `ExtractDataFromLogs` did not include DRWA slices. Result accumulation was inline in the loop.
- **After:** `drwaProc` registered and runs on every event. All 4 DRWA slices forwarded. `collectEventResults` is a dedicated method — adding future record types only requires adding a nil-check there.

### 12.5 Failure & Risk Analysis

- **Processor ordering dependency:** If a future processor is inserted before `drwaProc` and sets `processed: true` for `drwa*` events, DRWA processing silently stops. No guard against this.
- **`collectEventResults` second parameter ignored:** `_ string` (log hash). If a future record type needs the hash for deduplication, this signature must change.
- **Risk Level:** Low — this change fixes bugs rather than introducing them.

### 12.6 Test Analysis

- No integration test processes a block with all 4 DRWA event types and asserts all 4 slices in `PreparedLogsResults` are non-empty. This is the most important missing test — it would have caught the original pipeline bug.
- No test verifies processor ordering — that `drwaProc` intercepts `drwa*` events before `informativeProc`.

### 12.7 Cross-System Impact

- `PreparedLogsResults` now carries non-empty DRWA slices for the first time. `elasticProcessor.indexLogsData()` will now actually call `SerializeDRWA*` with real data.
- All existing processors unaffected — `drwaProc` only intercepts events with `drwa` prefix.

### 12.8 Final Decision

**Status: 🟢 APPROVE**

This is the central wiring that makes the entire DRWA feature work. Three things done correctly: `drwaProc` registration, DRWA forwarding (fixes the pipeline bug), and `collectEventResults` extraction. The one remaining open blocker for the full feature — missing index creation on startup — is not this file's responsibility.

---

## 13. `process/elasticproc/logsevents/serialize.go`

### 13.1 Change Scope

- **Files Changed:** `process/elasticproc/logsevents/serialize.go`
- **Change Type:** Feature
- **New stored state:** Yes — writes `drwa` sub-object into existing `tokens` ES index documents.

Two changes:
1. New routing branch added to `serializeToken` — `DrwaUpdate` checked first, before `TransferOwnership` and `ChangeToDynamic`
2. New `serializeTokenDrwa` function implementing Painless scripted upsert

### 13.2 Impacted System Flow

- **Flow:** DRWA Token Event → `tokens` Index Partial Update
- **Entry Point:** `serializeToken()` — called for every `TokenInfo` in `logsData.tokensInfo`
- **Exit Point:** `buffSlice.PutData(meta, serializedData)` — appends Painless scripted upsert to bulk request buffer
- **Key detail:** Painless script has two branches:
  - Branch 1 (first-write): `ctx._source.drwa = params.drwa`
  - Branch 2 (update): `ctx._source.drwa.putAll(params.drwa)`
  
  `serializedDrwa` is embedded twice — once as script parameter and once in the upsert body.

### 13.3 Invariant Analysis

- **Are invariants affected?** Yes — correctly for the routing, incorrectly for boolean fields.
- `putAll` correctly performs partial merge — only `drwa.*` fields touched, all other token fields preserved.
- `DrwaUpdate` checked first — correct routing priority.
- **Violation:** `omitempty` on boolean fields in `DrwaTokenInfo` means `GlobalPause: false`, `Regulated: false`, `StrictAuditorMode: false` are omitted from `serializedDrwa`. `putAll` will not reset them in ES — old `true` values persist silently. This is a **DRWA Golden Rule #3 (Consistency) violation** — ES drifts from on-chain state after every `false` transition.
- **Nil risk:** `serializeTokenDrwa` has no nil guard on `tokenData.Drwa`. `json.Marshal(nil)` returns `"null"`. Painless `putAll` on null throws NullPointerException in ES — hard failure, aborts entire block's indexing.

### 13.4 Change Explanation

- **Before:** Any `TokenInfo` with `DrwaUpdate: true` would fall through to the default path and replace the entire token document with only DRWA fields — wiping name, type, roles, and owner history.
- **After:** DRWA token updates are serialized as partial Painless script merges, preserving all non-DRWA fields.

### 13.5 Failure & Risk Analysis

- **`tokenData.Drwa` is nil:** Painless NullPointerException in ES. Hard failure — aborts block indexing. Should be caught at serializer level.
- **Token document does not exist:** Upsert creates `{identifier, token, drwa}` only — incomplete until a full token event is processed. Acceptable transient state.
- **`omitempty` stale state:** `GlobalPause: false` after `GlobalPause: true` leaves ES showing `globalPause: true` indefinitely. Silent.
- **Risk Level:** Medium — driven by `omitempty` boolean issue inherited from `DrwaTokenInfo`.

### 13.6 Test Analysis

- `TestSerializeTokensDrwaUpdate` in `serialize_test.go` covers the happy path (see File 15). No test for nil `Drwa`, no test for `GlobalPause: false` omission, no test for upsert body structure.

### 13.7 Cross-System Impact

- `tokens` ES index now receives partial update requests for DRWA-regulated tokens. Non-regulated tokens unaffected.
- Painless `putAll` is a shallow merge — if `DrwaTokenInfo` gains a nested sub-object field in future, `putAll` will replace the entire nested object rather than merging it.
- `tokens` index mapping must accept the `drwa` object field. If `dynamic: strict`, first write will be rejected.

### 13.8 Final Decision

**Status: 🔴 HOLD**

Required fixes:
1. Add nil guard in `serializeTokenDrwa`:
   ```go
   if tokenData.Drwa == nil {
       return nil, nil, fmt.Errorf("DrwaUpdate is true but Drwa is nil for token %s", tokenData.Token)
   }
   ```
2. Fix `omitempty` on boolean fields in `DrwaTokenInfo` (in `tokens.go`) — this automatically fixes the stale state issue here.

---

## 14. `process/elasticproc/logsevents/serializeDrwa.go`

### 14.1 Change Scope

- **Files Changed:** `process/elasticproc/logsevents/serializeDrwa.go`
- **Change Type:** Feature (New File)
- **New stored state:** Yes — implements the 4 `SerializeDRWA*` methods that write to 4 DRWA ES indices.

4 public methods + 1 private helper:
```go
SerializeDRWADenials(records []*data.DrwaDenialRecord, buffSlice *data.BufferSlice, index string) error
SerializeDRWAHolderCompliance(records []*data.DrwaHolderComplianceRecord, buffSlice *data.BufferSlice, index string) error
SerializeDRWAAttestations(records []*data.DrwaAttestationRecord, buffSlice *data.BufferSlice, index string) error
SerializeDRWATokenPolicies(records []*data.DrwaTokenPolicyRecord, buffSlice *data.BufferSlice, index string) error
prepareDRWARecord(id string, index string, record any) ([]byte, []byte, error)
```

### 14.2 Impacted System Flow

- **Flow:** DRWA Records → ES Bulk Buffer → Elasticsearch
- **Entry Point:** `elasticProcessor.indexDRWA*()` methods
- **Exit Point:** `buffSlice.PutData()` — appends ES bulk `index` operations
- **Key detail:** All 4 methods follow identical pattern: iterate → generate ID → call `prepareDRWARecord()` → write to buffer. Uses `{ "index" : ... }` (not `"update"`) — documents are created or replaced, not merged.

### 14.3 Invariant Analysis

- **Are invariants affected?** Yes — critical ID collision risk.

  **Document ID Generation:**

  | Method | ID Pattern | Collision Risk |
  |--------|-----------|----------------|
  | Denials | `{TxHash}-denial-{DenialCode}` | 🔴 HIGH |
  | HolderCompliance | `{TxHash}-{TokenID}-{Holder}` | 🟢 LOW |
  | Attestations | `{TxHash}-{EventType}-{Auditor}` | 🟡 MEDIUM |
  | TokenPolicies | `{TxHash}-{TokenID}-{EventType}` | 🟡 MEDIUM |

  **Critical — Denial ID Collision:**
  ```
  Transaction 0xabc123:
  - Transfer Alice → Bob denied (code 02)
  - Transfer Alice → Charlie denied (code 02)
  Both generate ID: "0xabc123-denial-02"
  Result: Second denial overwrites first in ES — data loss
  ```

  **Medium — Attestation collision:** Multiple auditors attesting same event type in one TX.

  **Medium — Token Policy collision:** Same policy type toggled multiple times in one TX.

### 14.4 Change Explanation

- **Before:** No DRWA serialization. `SerializeDRWA*` methods required by `DBLogsAndEventsHandler` interface had no implementation.
- **After:** All 4 methods implemented. Consistent pattern, DRY via `prepareDRWARecord()`, correct ES bulk API format.

### 14.5 Failure & Risk Analysis

- **Denial ID collision (Critical):** Multiple denials with same code in one TX overwrite each other. Compliance audit trail corrupted. Silent — ES overwrites without error.
- **Empty TxHash:** ID becomes `"-denial-02"` — invalid but accepted.
- **No input validation:** Missing required fields (TxHash, TokenID, DenialCode) produce malformed IDs silently.
- **No logging:** Silent failures make debugging difficult.
- **Risk Level:** High

### 14.6 Test Analysis

- No unit tests exist. Required:
  - Happy path (4 tests, one per method)
  - ID collision test for denials (critical)
  - Empty records slice
  - Empty TxHash
  - Special characters in fields (test `JsonEscape`)

### 14.7 Cross-System Impact

- Implements interface declared in `process/elasticproc/interface.go` — production path compiles.
- Called from `elasticProcessor.indexDRWA*()` — call sites match signatures exactly.
- `JsonEscape()` correctly sanitizes IDs — no injection risk.

### 14.8 Final Decision

**Status: 🔴 HOLD**

Required fixes before approval:
1. Fix denial ID collision — add sequence number:
   ```go
   for idx, record := range records {
       id := fmt.Sprintf("%s-denial-%s-%d", record.TxHash, record.DenialCode, idx)
   }
   ```
2. Add input validation for required fields (TxHash, TokenID, DenialCode not empty).
3. Create unit tests (minimum 80% coverage, 100% on ID generation logic).
4. Add logging: `log.Debug("serializing DRWA denials", "count", len(records), "index", index)`.

---

## 15. `process/elasticproc/logsevents/serialize_test.go`

### 15.1 Change Scope

- **Files Changed:** `process/elasticproc/logsevents/serialize_test.go`
- **Change Type:** Test Addition (New Test Function)
- **New stored state:** No.

New test function `TestSerializeTokensDrwaUpdate` inserted between `TestSerializeTokens` and `TestLogsAndEventsProcessor_SerializeDelegators`.

### 15.2 What the Test Claims to Verify

Calling `SerializeTokens` with `TokenInfo` where `DrwaUpdate = true` produces a correct ES bulk payload for a DRWA policy update. Specifically asserts:
1. No error returned
2. Exactly one buffer produced
3. Payload contains `"policyId":"policy-hotel-1"`
4. Payload contains `"tokenPolicyVersion":3`
5. Payload contains `"globalPause":true`
6. Payload contains Painless verb `ctx._source.drwa.putAll(params.drwa)`

### 15.3 Are the Assertions Correct?

**Yes — all six assertions are correct** for the code path they exercise. `require.Contains` is appropriate because the Painless source string is processed by `converters.FormatPainlessSource()` — exact whitespace is not guaranteed, but `ctx._source.drwa.putAll(params.drwa)` is stable (FormatPainlessSource only strips `\n` and `\t`, does not escape characters).

### 15.4 What the Test Does NOT Verify

- **Branch 1 of Painless script not tested:** `ctx._source.drwa = params.drwa` (first-write path). Asserting it requires the whitespace-collapsed form: `if (!ctx._source.containsKey('drwa') || ctx._source.drwa == null) {ctx._source.drwa = params.drwa} else {ctx._source.drwa.putAll(params.drwa)}`
- **Upsert body not verified:** `"upsert": {"identifier": "%s", "token": "%s", "drwa": %s}` — a regression corrupting the upsert body would cause ES 400 on first-write but test would pass.
- **`regulated: true` not asserted:** Present in input but not asserted in output.
- **`StrictAuditorMode: false` omission not documented:** Silently dropped due to `omitempty` — test neither asserts absence nor documents this as intentional.
- **`Drwa = nil` with `DrwaUpdate = true` not covered:** `json.Marshal(nil)` returns `"null"` — no panic, but Painless `putAll` on null fails at ES runtime.

### 15.5 Coverage Summary

| Scenario | Covered? |
|---|---|
| `DrwaUpdate = true`, happy path | ✅ Yes |
| Painless update verb (`putAll`) present | ✅ Yes |
| Painless first-write branch present | ❌ No |
| `regulated: true` present in output | ❌ Not asserted |
| `strictAuditorMode: false` omitted | ❌ Not asserted |
| Upsert body structure | ❌ Not asserted |
| `DrwaUpdate = true`, `Drwa = nil` | ❌ Not covered |

### 15.6 Final Decision

**Status: 🟢 APPROVE**

Test is correct. The `putAll` verb assertion is the most valuable guard — prevents silent semantic regression. Coverage gaps are real but do not make the test wrong.

Recommended follow-up:
1. Add `require.Contains` for `"regulated":true`.
2. Add assertions for upsert body (`"identifier":"HOTEL-1234"`, `"token":"HOTEL-1234"`).
3. Add test for `Drwa = nil` with `DrwaUpdate = true`.
4. Add test for first-write branch using whitespace-collapsed form.

---

## 16. `process/elasticproc/interface.go`

### 16.1 Change Scope

- **Files Changed:** `process/elasticproc/interface.go`
- **Change Type:** Feature
- **New stored state:** No — interface definitions are compile-time contracts.

4 new method signatures added to `DBLogsAndEventsHandler`:
```go
SerializeDRWADenials(records []*data.DrwaDenialRecord, buffSlice *data.BufferSlice, index string) error
SerializeDRWAHolderCompliance(records []*data.DrwaHolderComplianceRecord, buffSlice *data.BufferSlice, index string) error
SerializeDRWAAttestations(records []*data.DrwaAttestationRecord, buffSlice *data.BufferSlice, index string) error
SerializeDRWATokenPolicies(records []*data.DrwaTokenPolicyRecord, buffSlice *data.BufferSlice, index string) error
```

### 16.2 Impacted System Flow

- **Flow:** Interface Contract → Compile-time Enforcement
- **Entry Point:** `elasticProcessor.indexDRWA*()` — calls these methods via `DBLogsAndEventsHandler`
- **Exit Point:** `logsAndEventsProcessor.SerializeDRWA*()` in `serializeDrwa.go` — concrete implementations
- **Key detail:** This is a **breaking interface change**. Any type previously satisfying `DBLogsAndEventsHandler` must now implement all 4 new methods or fail to compile.

### 16.3 Invariant Analysis

- **Are invariants affected?** Yes — correctly.
- All 4 signatures follow the exact same pattern as existing `Serialize*` methods: `(records []*data.XxxRecord, buffSlice *data.BufferSlice, index string) error`.
- The `index string` parameter is passed explicitly — correct design, enables writing to different indices (test vs production) without changing implementation.
- Concrete implementation `logsAndEventsProcessor` satisfies the interface via `serializeDrwa.go` — confirmed. Production path compiles.

### 16.4 Change Explanation

- **Before:** `DBLogsAndEventsHandler` had no DRWA methods. Any call to `SerializeDRWA*` through this interface would not compile.
- **After:** Complete contract for all log and event serialization including DRWA. Enables dependency injection and testability.

### 16.5 Failure & Risk Analysis

- **Breaking change for mocks:** Any existing mock of `DBLogsAndEventsHandler` fails to compile until 4 new methods are added. Hard compile error — immediately visible.
- **Silent Failure Risk:** None — interface violations are compile errors in Go.
- **Risk Level:** Low

### 16.6 Test Analysis

- Any test file using a mock of `DBLogsAndEventsHandler` must be updated. If auto-generated (e.g. via `mockery`), must be regenerated.
- Recommended: add explicit compile-time interface satisfaction check:
  ```go
  var _ elasticproc.DBLogsAndEventsHandler = (*logsevents.logsAndEventsProcessor)(nil)
  ```

### 16.7 Cross-System Impact

- Breaking change for all implementors of `DBLogsAndEventsHandler`. Production code compiles. Test mocks must be updated.
- Approving this file does not unblock the full DRWA feature — the two High bugs (denial ID collision + indices not created on startup) still need fixing.

### 16.8 Final Decision

**Status: 🟢 APPROVE (with one recommendation)**

Clean, necessary, correctly structured interface extension. Signatures match implementations and call sites exactly. Add compile-time interface satisfaction check.

---

## 17. `process/elasticproc/elasticProcessor.go`

### 17.1 Change Scope

- **Files Changed:** `process/elasticproc/elasticProcessor.go`
- **Change Type:** Feature + Refactor
- **New stored state:** Yes — 4 new `indexDRWA*` methods write to 4 new ES indices.

Two changes:
1. **Refactor:** `SaveTransactions` body extracted into `indexLogsData` — all log/event-related indexing steps delegated to new private method.
2. **Feature:** 4 new DRWA indexing methods added and wired into `indexLogsData`:
```go
func (ei *elasticProcessor) indexDRWADenials(...)         error
func (ei *elasticProcessor) indexDRWAHolderCompliance(...) error
func (ei *elasticProcessor) indexDRWAAttestations(...)    error
func (ei *elasticProcessor) indexDRWATokenPolicies(...)   error
```

Each follows the established guard pattern:
```go
if len(records) == 0 || !ei.isIndexEnabled(elasticIndexer.DrwaDenialsIndex) {
    return nil
}
return ei.logsAndEventsProc.SerializeDRWA*(records, buffSlice, elasticIndexer.Drwa*Index)
```

### 17.2 Impacted System Flow

- **Flow:** Block Processing → Elasticsearch Bulk Write
- **Entry Point:** `SaveTransactions()` — called once per block
- **Exit Point:** `doBulkRequests()` — sends all accumulated bulk operations to ES
- **Key detail:** All indexing steps share a single `BufferSlice`. If any step before the DRWA calls in `indexLogsData` fails, all 4 DRWA calls are skipped and their data is permanently lost for that block — no retry or dead-letter mechanism.

### 17.3 Invariant Analysis

- **Are invariants affected?** Yes — correctly for the refactor, with one dependency issue.
- Refactor preserves existing order of all operations — no step removed or reordered.
- All 4 new methods correctly guard with `len(records) == 0 || !ei.isIndexEnabled(...)`.
- Atomicity maintained — failure in any step returns early, `doBulkRequests` never called, no partial write reaches ES.
- **Dependency issue:** `indexDRWATokenPolicies` is the last call in `indexLogsData` and is returned directly. A DRWA serialization error can abort an entire block's worth of transactions, tokens, and accounts from ES — consistent with existing behavior but worth noting.

### 17.4 Change Explanation

- **Before:** `SaveTransactions` was a single 60+ line function. No DRWA data was written — `DrwaDenials`, `DrwaHolderCompliance`, `DrwaAttestations`, `DrwaTokenPolicies` from `PreparedLogsResults` were populated but never consumed.
- **After:** `SaveTransactions` delegates log/event steps to `indexLogsData()`. DRWA records written to their respective ES indices as part of every block's processing cycle.

### 17.5 Failure & Risk Analysis

- **DRWA indices never created on startup (High):** Even if data arrives correctly, target indices do not exist on fresh deployment. Writes fail. This is the same unresolved bug from `constants.go`.
- **`isIndexEnabled` silent skip:** If DRWA indices not in `EnabledIndexes` config, methods return `nil` silently. No warning emitted.
- **`len(nil) == 0`:** If `logsData.DrwaTokenPolicies` is nil (due to missing forwarding — fixed in `logsAndEventsProcessor.go`), the guard handles it correctly — no panic, but data never written.
- **Risk Level:** Medium — refactor is low risk. DRWA additions inherit same risk profile as rest of pipeline.

### 17.6 Test Analysis

- No unit test for `indexLogsData` as a whole. No unit test for each `indexDRWA*` method individually — specifically the `isIndexEnabled` guard path and the happy path.
- No test covers the scenario where an earlier step in `indexLogsData` fails and verifies DRWA calls are correctly skipped.

### 17.7 Cross-System Impact

- `SaveTransactions` signature unchanged — no caller affected.
- 4 new `indexDRWA*` methods are private — no external interface change.
- `DBLogsAndEventsHandler` interface now requires `SerializeDRWA*` methods — any mock must implement all 4 or fail to compile.
- Depends on two unresolved bugs: `DrwaTokenPolicies` pipeline (fixed in `logsAndEventsProcessor.go`) and DRWA indices not created on startup (not fixed in any scanned file).

### 17.8 Final Decision

**Status: 🔴 HOLD**

The refactor is clean and correct — `indexLogsData` is a well-scoped extraction. The 4 new `indexDRWA*` methods are correctly implemented and follow the established pattern exactly. However this change cannot be approved in isolation because it depends on two unresolved bugs:

1. **DRWA indices never created on startup** — add all 4 DRWA index constants to the `indexes` slice and all 4 policy constants to `indexesPolicies` in this file.
2. **`DrwaTokenPolicies` pipeline** — fixed in `logsAndEventsProcessor.go`, must be deployed together.

The `indexLogsData` refactor can be approved independently if needed — it introduces no new bugs.

---

## Final Summary

### Overall Feature Status: 🔴 NOT READY FOR PRODUCTION

### Decisions by File

| # | File | Status | Blocker |
|---|------|--------|---------|
| 1 | `constants.go` | 🔴 HOLD | Indices/policies not wired into startup |
| 2 | `data/drwa.go` | 🔴 HOLD | `omitempty` on 7 boolean fields |
| 3 | `data/drwa_test.go` | 🟡 APPROVE w/ notes | Add omitempty-exposing tests |
| 4 | `data/tokens.go` | 🔴 HOLD | `omitempty` on 3 boolean fields + nil guard |
| 5 | `data/mrv.go` | 🔴 HOLD | `omitempty` on critical fields + no event processor |
| 6 | `data/logs.go` | 🔴 HOLD | Depends on `logsAndEventsProcessor.go` fix |
| 7 | `logsData.go` | 🟢 APPROVE | — |
| 8 | `logsevents/interface.go` | 🟢 APPROVE | — |
| 9 | `drwaEventsProcessor.go` | 🔴 HOLD | 4 unhandled events, topic[3] bug, no denial validation |
| 10 | `drwaEventsProcessor_test.go` | 🟡 APPROVE w/ notes | Add denial test |
| 11 | `drwaEventsProcessor_benchmark_test.go` | 🟡 APPROVE w/ notes | Fix boolean format |
| 12 | `logsAndEventsProcessor.go` | 🟢 APPROVE | — |
| 13 | `serialize.go` | 🔴 HOLD | Nil guard missing + omitempty stale state |
| 14 | `serializeDrwa.go` | 🔴 HOLD | Denial ID collision (data loss) |
| 15 | `serialize_test.go` | 🟢 APPROVE | — |
| 16 | `elasticproc/interface.go` | 🟢 APPROVE | — |
| 17 | `elasticProcessor.go` | 🔴 HOLD | Indices not created on startup |

### Mandatory Fixes Before Production (Ordered by Severity)

1. **🔴 CRITICAL — Denial ID collision** (`serializeDrwa.go`): Multiple denials with same code in one TX overwrite each other. Add sequence number to ID.
2. **🔴 CRITICAL — DRWA/MRV indices never created on startup** (`constants.go`, `elasticProcessor.go`): Wire all index and policy constants into startup provisioning slices.
3. **🔴 CRITICAL — `omitempty` on boolean fields is a Golden Rule #3 sync drift violation** (`data/drwa.go`, `data/tokens.go`): Boolean fields transitioning `true → false` are silently omitted from JSON — ES drifts from on-chain state indefinitely, identical to the sync drift failure scenario in the DRWA domain brief.
4. **🔴 HIGH — 4 DRWA events not handled** (`drwaEventsProcessor.go`): `drwaTransferAllowedEvent`, `drwaMetadataProtectionEvent`, `drwaGovernanceProposedEvent`, `drwaGovernanceAcceptedEvent` — governance and metadata protection audit trail completely missing. `drwaAuditorProposedEvent` and `drwaAuditorAcceptedEvent` are correctly handled.
5. **🔴 HIGH — Code 0 priority not validated** (`drwaEventsProcessor.go`): DRWA Golden Rule #4 requires Code 0 (`PolicyNotSynced`) to be the highest-priority denial. No validation ensures Code 0 is correctly indexed — a malformed Code 0 event silently corrupts the most critical denial audit trail.
6. **🔴 HIGH — `ReportHash` has `omitempty`** (`data/mrv.go`): Violates MRV Evidence Binding (Golden Rule #2).
7. **🔴 HIGH — MRV Buffer Integrity not tracked** (`data/mrv.go`): No `bufferDeducted` or `bufferPct` field — ES audit trail cannot prove Golden Rule #3 compliance for any credit batch.
8. **🔴 HIGH — MRV 8-Gate results not captured** (`data/mrv.go`): `ProofStatus` string cannot represent which of G1–G8 passed or failed. Add gate-level fields.
9. **🔴 HIGH — `ReportID` not used as ES document `_id`** (`data/mrv.go`, MRV serializer): Using `ReportID` as `_id` enforces No Double Issuance (Golden Rule #1) at the ES layer for free.
10. **🔴 HIGH — Nil guard missing** (`serialize.go`): `tokenData.Drwa = nil` with `DrwaUpdate = true` causes Painless NullPointerException in ES, aborting entire block's indexing.
11. **🟡 MEDIUM — Topic[3] skip in attestation** (`drwaEventsProcessor.go`): Either document why it is unused or parse it.
12. **🟡 MEDIUM — No denial code validation** (`drwaEventsProcessor.go`): Accept only codes 0-11 per DRWA domain brief.
13. **🟡 MEDIUM — No unit tests for `serializeDrwa.go`**: Add happy path, ID collision, and edge case tests.
14. **🟡 MEDIUM — No MRV event processor found** (`data/mrv.go`): MRV indexing pipeline may be incomplete.
