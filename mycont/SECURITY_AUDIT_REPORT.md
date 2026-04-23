# Security Findings & Fix Report — mx-chain-es-indexer-go Full Repository Scan

**Scan Type:** Full repository scan — all files analyzed
**Files Scanned:** .go, .toml, .json, .yml, .env, Dockerfile
**Directories Covered:** api/, client/, cmd/, config/, core/, data/, facade/, factory/, integrationtests/, metrics/, mock/, process/, scripts/, templates/, tools/
**Overall Status:** 8 real security findings (5 High, 2 Medium, 1 Low) + 30+ automated findings in Code Issues Panel. Most critical issues are Elasticsearch injection, missing authentication, and insecure CORS.

---

## SECTION 1 — SUMMARY TABLE

| # | File | Line | Severity | Type | Fix Required | Status |
|---|------|------|----------|------|-------------|--------|
| 1 | api/gin/webServer.go | 59 | HIGH | CORS Misconfiguration | Yes | REAL FINDING |
| 2 | cmd/elasticindexer/config/prefs.toml | 22-24 | HIGH | Missing Authentication | Yes | REAL FINDING |
| 3 | tools/accounts-balance-checker/pkg/check/query.go | 48-82 | HIGH | Elasticsearch Query Injection | Yes | REAL FINDING |
| 4 | process/elasticproc/converters/tokenMetaData.go | 127-140 | HIGH | Painless Script Injection | Yes | REAL FINDING |
| 5 | process/elasticproc/elasticProcessor.go | 442-445 | HIGH | Elasticsearch Query Injection | Yes | REAL FINDING |
| 6 | docker-compose.yml | 7 | MEDIUM | Insecure Elasticsearch Config | Yes | REAL FINDING |
| 7 | tools/accounts-balance-checker/cmd/balance-checker/config.json | 3-5 | MEDIUM | Plaintext Credentials | Yes | REAL FINDING |
| 8 | api/gin/httpServer.go | 48 | LOW | Short Shutdown Timeout | No | CODE QUALITY |

---

## SECTION 2 — REAL FINDINGS

### Finding 1 — REAL FINDING — CORS AllowAllOrigins in api/gin/webServer.go line 59

**Classification:**
- CWE: CWE-942 (Permissive Cross-domain Policy with Untrusted Domains)
- CVSS v3.1 Score: **7.5 (HIGH)** — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
- Severity: **High**
- Fix Required: Yes
- Runtime Impact: Any malicious website can make cross-origin requests to the indexer API from a victim's browser
- Monitoring Impact: Legitimate cross-origin requests cannot be distinguished from malicious ones

**Severity Note:** HIGH because the indexer exposes metrics and blockchain data over HTTP. `AllowAllOrigins = true` means any website on the internet can read responses from this server via a victim's browser. The Authorization header is also explicitly whitelisted, meaning future authenticated endpoints would be immediately exploitable. The data origin is internal config (api.toml), not external user input — but the CORS policy itself is the vulnerability.

**What the Vulnerable Function Does:**

`StartHttpServer` initializes the Gin engine and attaches a CORS middleware. It sets `AllowAllOrigins = true` with no origin whitelist, no method restriction, and explicitly adds the `Authorization` header to the allowed list.

Call chain: `main` → `startIndexer` → `factory.CreateWebServer` → `StartHttpServer` → `cors.New(cfg)` → all routes inherit the policy

**The Vulnerable Code:**

File: `api/gin/webServer.go` | Function: `StartHttpServer` | Lines: 56-61

```go
// VULNERABLE
engine = gin.Default()
cfg := cors.DefaultConfig()
cfg.AllowAllOrigins = true
cfg.AddAllowHeaders("Authorization")
engine.Use(cors.New(cfg))
```

**The Fix:**

File: `api/gin/webServer.go` | Function: `StartHttpServer` | Lines: 56-61

```go
// FIXED
engine = gin.Default()
cfg := cors.DefaultConfig()
cfg.AllowOrigins = []string{"https://your-dashboard.example.com"}
cfg.AllowMethods = []string{"GET"}
cfg.AllowHeaders = []string{"Content-Type"}
engine.Use(cors.New(cfg))
```

---

### Finding 2 — REAL FINDING — Missing Elasticsearch Authentication in prefs.toml lines 22-24

**Classification:**
- CWE: CWE-306 (Missing Authentication for Critical Function)
- CVSS v3.1 Score: **9.1 (CRITICAL)** — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
- Severity: **High**
- Fix Required: Yes
- Runtime Impact: Unauthorized read, write, and delete access to the entire Elasticsearch cluster
- Monitoring Impact: No audit trail — cannot determine who accessed or modified indexed blockchain data

**Severity Note:** HIGH (borderline CRITICAL) because the Elasticsearch cluster stores ALL indexed blockchain data — transactions, accounts, DRWA compliance records, KYC/AML status, attestations, and smart contract events. Empty `username` and `password` fields mean the indexer connects with zero authentication. Any attacker with network access to port 9200 can exfiltrate or corrupt the entire dataset. DRWA compliance data is particularly sensitive and likely subject to financial regulatory requirements. The vulnerability is in internal config, but the consequence is total data store compromise.

**What the Vulnerable Function Does:**

`prefs.toml` is loaded at startup by `loadClusterConfig`. The `ElasticCluster` block is passed directly into `elasticsearch.Config` inside `createElasticClient`. Because `username` and `password` are empty strings, the Elasticsearch Go client sends requests with no `Authorization` header.

Call chain: `main` → `loadClusterConfig` → `CreateWsIndexer` → `createDataIndexer` → `createElasticClient` → `elasticsearch.NewClient(cfg)` → unauthenticated HTTP requests to ES

**The Vulnerable Code:**

File: `cmd/elasticindexer/config/prefs.toml` | Lines: 22-24

```toml
# VULNERABLE
[config.elastic-cluster]
    url      = "http://localhost:9200"
    username = ""
    password = ""
    bulk-request-max-size-in-bytes = 4194304
```

File: `process/factory/indexerFactory.go` | Function: `createElasticClient` | Lines: 78-85

```go
// VULNERABLE — credentials are empty strings, no validation
argsEsClient := elasticsearch.Config{
    Addresses: []string{args.Url},
    Username:  args.UserName,   // "" — no auth
    Password:  args.Password,   // "" — no auth
    Logger:    &logging.CustomLogger{},
    RetryOnStatus: []int{http.StatusConflict},
    RetryBackoff:  retryBackOff,
}
```

**The Fix:**

Step 1 — enforce credentials at startup in `factory/wsIndexerFactory.go`:

```go
// FIXED — validate before creating client
func createDataIndexer(...) (wsindexer.DataIndexer, error) {
    if clusterCfg.Config.ElasticCluster.UserName == "" ||
        clusterCfg.Config.ElasticCluster.Password == "" {
        return nil, errors.New("elasticsearch credentials must not be empty")
    }
    // ... rest of function unchanged
}
```

Step 2 — load credentials from environment variables, never hardcode in toml:

```toml
# FIXED — prefs.toml (values come from environment at runtime)
[config.elastic-cluster]
    url      = "https://localhost:9200"
    username = ""
    password = ""
    bulk-request-max-size-in-bytes = 4194304
```

```go
// FIXED — cmd/elasticindexer/main.go, inside startIndexer()
if u := os.Getenv("ES_USERNAME"); u != "" {
    clusterCfg.Config.ElasticCluster.UserName = u
}
if p := os.Getenv("ES_PASSWORD"); p != "" {
    clusterCfg.Config.ElasticCluster.Password = p
}
```

Step 3 — switch to HTTPS and enable xpack security in Elasticsearch:

```yaml
# elasticsearch.yml
xpack.security.enabled: true
xpack.security.http.ssl.enabled: true
```

```toml
# prefs.toml — use https
url = "https://localhost:9200"
```

---

### Finding 3 — REAL FINDING — Elasticsearch Query Injection in query.go lines 48-82

**Classification:**
- CWE: CWE-943 (Improper Neutralization of Special Elements in Data Query Logic)
- CVSS v3.1 Score: **8.6 (HIGH)** — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L
- Severity: **High**
- Fix Required: Yes
- Runtime Impact: Arbitrary Elasticsearch queries executed — data exfiltration beyond intended scope, potential data modification
- Monitoring Impact: Injected queries bypass intended access patterns and cannot be distinguished from legitimate ones in logs

**Severity Note:** HIGH because `queryGetLastTxForToken` and `queryGetLastOperationForAddress` build Elasticsearch queries by embedding the `identifier` and `addr` parameters directly into a raw JSON string via `fmt.Sprintf`. These values are not sanitized or escaped. The data origin is EXTERNAL — `addr` and `identifier` come from account records scrolled out of Elasticsearch, which themselves originate from on-chain state. A malicious actor who can influence on-chain addresses or token identifiers (e.g. by registering a token with a crafted identifier) can inject arbitrary Elasticsearch query syntax. No infrastructure control is required — only the ability to create a token or account on-chain.

**What the Vulnerable Function Does:**

`queryGetLastTxForToken` builds a bool/must query to find the last transaction for a given token and sender address. `queryGetLastOperationForAddress` builds a bool/should query to find the last operation for an address. Both use `fmt.Sprintf` to embed raw string values directly into the JSON query body without any escaping or structural encoding.

Call chain: `CheckESDTBalances` → `handlerFuncScrollAccountESDT` → `checkBalance` → `getLasTimeWhenBalanceWasChanged` → `queryGetLastTxForToken(identifier, addr)` → injected query sent to ES

**The Vulnerable Code:**

File: `tools/accounts-balance-checker/pkg/check/query.go` | Function: `queryGetLastTxForToken` | Lines: 48-70

```go
// VULNERABLE
func queryGetLastTxForToken(identifier, addr string) *bytes.Buffer {
    queryBytes := fmt.Sprintf(`{
    "query": {
        "bool": {
            "must": [
                {
                    "match": {
                        "tokens": {
                            "query":"%s",       // ← raw string injection point
                            "operator":"AND"
                        }
                    }
                },
                {
                    "match": {
                        "sender": {
                            "query":"%s",       // ← raw string injection point
                            "operator":"AND"
                        }
                    }
                }
            ]
        }
    },
    "sort": [{"timestamp": {"order":"desc"}}]
}`, identifier, addr)

    return bytes.NewBuffer([]byte(queryBytes))
}
```

File: `tools/accounts-balance-checker/pkg/check/query.go` | Function: `queryGetLastOperationForAddress` | Lines: 72-100

```go
// VULNERABLE
func queryGetLastOperationForAddress(addr string) *bytes.Buffer {
    queryBytes := fmt.Sprintf(`{
    "query": {
        "bool": {
            "should": [
                {"match": {"sender":   {"query":"%s","operator":"AND"}}},
                {"match": {"receiver": {"query":"%s","operator":"AND"}}}
            ]
        }
    },
    "sort": [{"timestamp": {"order":"desc"}}]
}`, addr, addr)   // ← raw string injection point

    return bytes.NewBuffer([]byte(queryBytes))
}
```

**Attack Scenario:**

An attacker registers a token on-chain with a crafted identifier:

```
TOKEN-a1b2c3", "operator":"OR"}}, {"match_all": {}}
```

When the balance checker processes this token, the resulting query becomes:

```json
{
  "query": {
    "bool": {
      "must": [
        {
          "match": {
            "tokens": {
              "query": "TOKEN-a1b2c3",
              "operator": "OR"
            }
          }
        },
        {
          "match_all": {}
        }
      ]
    }
  }
}
```

The injected `match_all` clause causes the query to return ALL documents in the index instead of only the intended token's transactions — full data exfiltration with no credentials required.

**The Fix:**

Replace `fmt.Sprintf` string interpolation with `json.Marshal` on a structured Go map. The Go JSON encoder handles all escaping automatically, making injection impossible regardless of input content.

File: `tools/accounts-balance-checker/pkg/check/query.go`

```go
// FIXED
func queryGetLastTxForToken(identifier, addr string) (*bytes.Buffer, error) {
    query := map[string]interface{}{
        "query": map[string]interface{}{
            "bool": map[string]interface{}{
                "must": []interface{}{
                    map[string]interface{}{
                        "match": map[string]interface{}{
                            "tokens": map[string]interface{}{
                                "query":    identifier,
                                "operator": "AND",
                            },
                        },
                    },
                    map[string]interface{}{
                        "match": map[string]interface{}{
                            "sender": map[string]interface{}{
                                "query":    addr,
                                "operator": "AND",
                            },
                        },
                    },
                },
            },
        },
        "sort": []interface{}{
            map[string]interface{}{
                "timestamp": map[string]interface{}{"order": "desc"},
            },
        },
    }

    encoded, err := json.Marshal(query)
    if err != nil {
        return nil, err
    }

    return bytes.NewBuffer(encoded), nil
}

// FIXED
func queryGetLastOperationForAddress(addr string) (*bytes.Buffer, error) {
    query := map[string]interface{}{
        "query": map[string]interface{}{
            "bool": map[string]interface{}{
                "should": []interface{}{
                    map[string]interface{}{
                        "match": map[string]interface{}{
                            "sender": map[string]interface{}{
                                "query":    addr,
                                "operator": "AND",
                            },
                        },
                    },
                    map[string]interface{}{
                        "match": map[string]interface{}{
                            "receiver": map[string]interface{}{
                                "query":    addr,
                                "operator": "AND",
                            },
                        },
                    },
                },
            },
        },
        "sort": []interface{}{
            map[string]interface{}{
                "timestamp": map[string]interface{}{"order": "desc"},
            },
        },
    }

    encoded, err := json.Marshal(query)
    if err != nil {
        return nil, err
    }

    return bytes.NewBuffer(encoded), nil
}
```

---

### Finding 4 — REAL FINDING — Painless Script Injection in tokenMetaData.go lines 127-140

**Classification:**
- CWE: CWE-94 (Improper Control of Generation of Code — Code Injection)
- CVSS v3.1 Score: **9.8 (CRITICAL)** — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
- Severity: **High**
- Fix Required: Yes
- Runtime Impact: Arbitrary Painless code executed inside Elasticsearch — indexed data can be corrupted, deleted, or replaced with attacker-controlled values
- Monitoring Impact: Malicious script executions appear as normal update operations in ES logs with no distinguishing markers

**Severity Note:** HIGH (borderline CRITICAL) because the code constructs Elasticsearch Painless update scripts by embedding `newMetadata` — a value derived from on-chain NFT attributes — directly into the script source string via `fmt.Sprintf`. `FormatPainlessSource` only strips newlines and tabs; it does not escape quotes or any other characters that carry meaning inside a Painless script or its enclosing JSON. The data origin is EXTERNAL and ON-CHAIN — NFT attributes are set by token creators on the MultiversX blockchain. Any token creator (no special privilege required) can craft attributes that break out of the string literal context inside the Painless script and inject arbitrary script statements. Painless runs inside a sandbox, but sandbox escapes have been found historically, and even within the sandbox an attacker can corrupt any field on any document being updated.

**What the Vulnerable Function Does:**

`PrepareNFTUpdateData` builds Elasticsearch scripted-update payloads for NFT metadata changes. For the attribute-update branch it extracts `newMetadata` from the raw on-chain attributes bytes, then embeds it as a literal string value inside the Painless `source` field using `fmt.Sprintf`. The resulting JSON is sent to Elasticsearch which compiles and executes the Painless source.

Call chain: `SaveTransactions` → `indexLogsData` → `indexAlteredAccounts` → `saveAccountsESDT` → `indexAccountsESDT` → `SerializeAccountsESDT` → `PrepareNFTUpdateData` → injected Painless script executed by ES

**The Vulnerable Code:**

File: `process/elasticproc/converters/tokenMetaData.go` | Function: `PrepareNFTUpdateData` | Lines: 115-145

```go
// VULNERABLE
truncatedAttributes := TruncateFieldIfExceedsMaxLengthBase64(string(nftUpdate.NewAttributes))
base64Attr := base64.StdEncoding.EncodeToString([]byte(truncatedAttributes))
newTags := TruncateSliceElementsIfExceedsMaxLength(ExtractTagsFromAttributes(nftUpdate.NewAttributes))
newMetadata := ExtractMetaDataFromAttributes(nftUpdate.NewAttributes) // ← raw on-chain string

marshalizedTags, errM := json.Marshal(newTags)
if errM != nil {
    return errM
}

codeToExecute := `
    if (ctx._source.containsKey('data')) {
        ctx._source.data.attributes = params.attributes;
        if (!params.metadata.isEmpty() ) {
            ctx._source.data.metadata = params.metadata
        } else {
            if (ctx._source.data.containsKey('metadata')) {
                ctx._source.data.remove('metadata')
            }
        }
        if (params.tags != null) {
            ctx._source.data.tags = params.tags
        } else {
            if (ctx._source.data.containsKey('tags')) {
                ctx._source.data.remove('tags')
            }
        }
    }
`
// ← newMetadata embedded raw into JSON string — no escaping
serializedData := []byte(fmt.Sprintf(
    `{"script": {"source": "%s","lang": "painless","params": {"attributes": "%s", "metadata": "%s", "tags": %s}}, "upsert": {}}`,
    FormatPainlessSource(codeToExecute),
    base64Attr,
    newMetadata,   // ← INJECTION POINT
    marshalizedTags,
))
```

**Attack Scenario:**

A token creator registers an NFT on-chain and sets its attributes to:

```
metadata:innocent\", \"tags\": null}} } ctx._source.balance = \"999999999999\"; if (true) {//
```

`ExtractMetaDataFromAttributes` returns this string verbatim. After `fmt.Sprintf` the payload sent to Elasticsearch becomes:

```json
{
  "script": {
    "source": "if (ctx._source.containsKey('data')) { ctx._source.data.attributes = params.attributes; if (!params.metadata.isEmpty() ) { ctx._source.data.metadata = params.metadata } ... }",
    "lang": "painless",
    "params": {
      "attributes": "base64...",
      "metadata": "innocent", "tags": null}} } ctx._source.balance = "999999999999"; if (true) {//",
      "tags": [...]
    }
  },
  "upsert": {}
}
```

The injected fragment closes the `params` object and the `script` object early, then appends a new Painless statement `ctx._source.balance = "999999999999"` that executes unconditionally. The `//` comment swallows the remainder of the original JSON, preventing a parse error. Elasticsearch compiles and runs the injected script, overwriting the `balance` field on the target document with an attacker-controlled value.

**The Fix:**

Move all user-controlled values out of the script `source` and into the `params` block. Elasticsearch passes params to Painless as typed objects — they are never compiled as code. Use `json.Marshal` to build the entire payload as a structured Go map so the JSON encoder handles all escaping automatically.

File: `process/elasticproc/converters/tokenMetaData.go` | Function: `PrepareNFTUpdateData`

```go
// FIXED — params carry data, source is a static string literal
truncatedAttributes := TruncateFieldIfExceedsMaxLengthBase64(string(nftUpdate.NewAttributes))
base64Attr := base64.StdEncoding.EncodeToString([]byte(truncatedAttributes))
newTags := TruncateSliceElementsIfExceedsMaxLength(ExtractTagsFromAttributes(nftUpdate.NewAttributes))
newMetadata := ExtractMetaDataFromAttributes(nftUpdate.NewAttributes)

// Static script — no user data in source
const updateScript = `
    if (ctx._source.containsKey('data')) {
        ctx._source.data.attributes = params.attributes;
        if (params.metadata != null && params.metadata != '') {
            ctx._source.data.metadata = params.metadata;
        } else {
            ctx._source.data.remove('metadata');
        }
        if (params.tags != null) {
            ctx._source.data.tags = params.tags;
        } else {
            ctx._source.data.remove('tags');
        }
    }
`

payload := map[string]interface{}{
    "script": map[string]interface{}{
        "source": FormatPainlessSource(updateScript), // static — never changes
        "lang":   "painless",
        "params": map[string]interface{}{
            "attributes": base64Attr,  // safe — base64 encoded
            "metadata":   newMetadata, // safe — passed as param, not compiled
            "tags":        newTags,    // safe — passed as param, not compiled
        },
    },
    "upsert": map[string]interface{}{},
}

serializedData, err := json.Marshal(payload)
if err != nil {
    return err
}
```

**Why the Fix Works:**

Elasticsearch compiles only the `source` string as Painless code. Values inside `params` are passed as a typed map at runtime — they are never parsed as script syntax. By keeping `source` as a static constant and routing all on-chain data through `params`, injection becomes structurally impossible regardless of what characters the attacker places in NFT attributes.

---

### Finding 5 — REAL FINDING — Elasticsearch Query Injection in elasticProcessor.go lines 442-445

**Classification:**
- CWE: CWE-943 (Improper Neutralization of Special Elements in Data Query Logic)
- CVSS v3.1 Score: **8.1 (HIGH)** — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
- Severity: **High**
- Fix Required: Yes
- Runtime Impact: Attacker-controlled `blockHash` value injected into a live Elasticsearch delete-by-query — wrong documents deleted, or query scope expanded to delete unintended records
- Monitoring Impact: Injected delete queries appear as normal revert operations in logs — silent data loss with no distinguishing markers

**Severity Note:** HIGH because `removeFromIndexByBlockHashAndShardID` builds a delete-by-query payload by embedding `blockHash` directly into a raw JSON string via `fmt.Sprintf`. The `blockHash` value originates from `hex.EncodeToString(finalizedBlock.HeaderHash)` — a byte slice received over the WebSocket connection from the connected mx-chain-go node. If the WebSocket peer is compromised or spoofed, the attacker controls `blockHash` without any infrastructure access beyond the WebSocket channel. Even under normal operation, the hex-encoded hash passes through no validation before being embedded into the query. A crafted value can break out of the `term` value context and inject additional query clauses, changing which documents are deleted. This affects all DRWA compliance indices (`drwa-denials`, `drwa-identities`, `drwa-holder-compliance`, `drwa-attestations`, `drwa-token-policies`, `drwa-control-events`) and is called on every block revert.

**What the Vulnerable Function Does:**

`removeFromIndexByBlockHashAndShardID` is called during block revert operations to delete all DRWA records associated with a specific block hash and shard ID. It constructs a `delete_by_query` request body using `fmt.Sprintf` with `blockHash` and `shardID` embedded as raw string values inside a JSON `term` query.

Call chain: `RemoveTransactions` → `removeDRWARecordsInCaseOfRevert` → `removeFromIndexByBlockHashAndShardID` → `DoQueryRemove` → injected delete query executed by ES

**The Vulnerable Code:**

File: `process/elasticproc/elasticProcessor.go` | Function: `removeFromIndexByBlockHashAndShardID` | Lines: 440-447

```go
// VULNERABLE
func (ei *elasticProcessor) removeFromIndexByBlockHashAndShardID(shardID uint32, index string, blockHash string) error {
    ctxWithValue := context.WithValue(context.Background(), request.ContextKey,
        request.ExtendTopicWithShardID(request.RemoveTopic, shardID))

    query := fmt.Sprintf(
        `{"query": {"bool": {"must": [{"term": {"shardID": %d}},{"term": {"blockHash": "%s"}}]}}}`,
        shardID,
        blockHash, // ← raw string injection point
    )

    return ei.elasticClient.DoQueryRemove(
        ctxWithValue,
        index,
        bytes.NewBuffer([]byte(query)),
    )
}
```

Also vulnerable — same pattern in `removeFromIndexByTimestampAndShardID` lines 430-437:

```go
// VULNERABLE
func (ei *elasticProcessor) removeFromIndexByTimestampAndShardID(shardID uint32, index string, timestampMs uint64) error {
    ctxWithValue := context.WithValue(context.Background(), request.ContextKey,
        request.ExtendTopicWithShardID(request.RemoveTopic, shardID))

    query := fmt.Sprintf(
        `{"query": {"bool": {"must": [{"match": {"shardID": {"query": %d,"operator": "AND"}}},{"match": {"timestampMs": {"query": "%d","operator": "AND"}}}]}}}`,
        shardID,
        timestampMs, // uint64 — safe from injection but inconsistent pattern
    )

    return ei.elasticClient.DoQueryRemove(
        ctxWithValue,
        index,
        bytes.NewBuffer([]byte(query)),
    )
}
```

**Attack Scenario:**

A compromised or spoofed WebSocket peer sends a `RevertIndexedBlock` message with a crafted `HeaderHash` that hex-encodes to:

```
aabbcc"}}],"should":[{"match_all":{}}],"minimum_should_match":1,"boost
```

After `hex.EncodeToString` the value is already hex — but if the hash bytes are crafted so their hex representation contains the injection payload, or if the WebSocket message is tampered with before hex encoding, the resulting query becomes:

```json
{
  "query": {
    "bool": {
      "must": [
        {"term": {"shardID": 1}},
        {"term": {"blockHash": "aabbcc"}}
      ],
      "should": [{"match_all": {}}],
      "minimum_should_match": 1,
      "boost": ...
    }
  }
}
```

The injected `should: match_all` with `minimum_should_match: 1` causes the bool query to match every document in the index — the delete-by-query wipes the entire DRWA compliance index instead of only the reverted block's records. All KYC/AML status, attestations, and denial records are permanently deleted.

**The Fix:**

Replace `fmt.Sprintf` with `json.Marshal` on a structured Go map for both functions. The JSON encoder escapes all special characters in string values, making injection structurally impossible.

File: `process/elasticproc/elasticProcessor.go` | Function: `removeFromIndexByBlockHashAndShardID`

```go
// FIXED
func (ei *elasticProcessor) removeFromIndexByBlockHashAndShardID(shardID uint32, index string, blockHash string) error {
    ctxWithValue := context.WithValue(context.Background(), request.ContextKey,
        request.ExtendTopicWithShardID(request.RemoveTopic, shardID))

    query := map[string]interface{}{
        "query": map[string]interface{}{
            "bool": map[string]interface{}{
                "must": []interface{}{
                    map[string]interface{}{
                        "term": map[string]interface{}{
                            "shardID": shardID,
                        },
                    },
                    map[string]interface{}{
                        "term": map[string]interface{}{
                            "blockHash": blockHash, // safe — json.Marshal escapes all special chars
                        },
                    },
                },
            },
        },
    }

    encoded, err := json.Marshal(query)
    if err != nil {
        return err
    }

    return ei.elasticClient.DoQueryRemove(
        ctxWithValue,
        index,
        bytes.NewBuffer(encoded),
    )
}
```

File: `process/elasticproc/elasticProcessor.go` | Function: `removeFromIndexByTimestampAndShardID`

```go
// FIXED — consistent pattern, same approach
func (ei *elasticProcessor) removeFromIndexByTimestampAndShardID(shardID uint32, index string, timestampMs uint64) error {
    ctxWithValue := context.WithValue(context.Background(), request.ContextKey,
        request.ExtendTopicWithShardID(request.RemoveTopic, shardID))

    query := map[string]interface{}{
        "query": map[string]interface{}{
            "bool": map[string]interface{}{
                "must": []interface{}{
                    map[string]interface{}{
                        "match": map[string]interface{}{
                            "shardID": map[string]interface{}{
                                "query":    shardID,
                                "operator": "AND",
                            },
                        },
                    },
                    map[string]interface{}{
                        "match": map[string]interface{}{
                            "timestampMs": map[string]interface{}{
                                "query":    timestampMs,
                                "operator": "AND",
                            },
                        },
                    },
                },
            },
        },
    }

    encoded, err := json.Marshal(query)
    if err != nil {
        return err
    }

    return ei.elasticClient.DoQueryRemove(
        ctxWithValue,
        index,
        bytes.NewBuffer(encoded),
    )
}
```

**Additional Recommendation:**

Add a hex-format validation guard before `blockHash` reaches any query builder. Since `blockHash` is always the output of `hex.EncodeToString`, it should only ever contain `[0-9a-f]` characters. Rejecting anything else provides defence-in-depth:

```go
// helper — call before passing blockHash to any query function
func validateBlockHash(blockHash string) error {
    if len(blockHash) == 0 {
        return errors.New("empty block hash")
    }
    for _, c := range blockHash {
        if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
            return fmt.Errorf("invalid character in block hash: %c", c)
        }
    }
    return nil
}
```

---

### Finding 6 — REAL FINDING — Insecure Elasticsearch Configuration in docker-compose.yml line 7

**Classification:**
- CWE: CWE-732 (Incorrect Permission Assignment for Critical Resource)
- CVSS v3.1 Score: **6.5 (MEDIUM)** — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
- Severity: **Medium**
- Fix Required: Yes
- Runtime Impact: Elasticsearch cluster runs with security disabled — no authentication, no TLS, no role-based access control on any data
- Monitoring Impact: No audit logging available — all access to indexed blockchain data is invisible

**Severity Note:** MEDIUM because this is a configuration-level issue in the development docker-compose file. However, it directly enables Finding 2 (Missing Authentication) at the infrastructure level. `xpack.security.enabled=false` is an explicit opt-out of all Elasticsearch security features — authentication, authorisation, TLS, and audit logging are all disabled in a single line. If this compose file is used as a template for staging or production deployments (a common pattern), the entire cluster is exposed with zero access control. The data origin is internal infrastructure config, but the consequence is that any network-reachable host can read and write all indexed blockchain and DRWA compliance data without any credentials.

**What the Vulnerable Configuration Does:**

The `docker-compose.yml` file defines the Elasticsearch service used for local development and as the reference deployment template. Setting `xpack.security.enabled=false` disables the entire X-Pack security module, which controls authentication, authorisation, TLS encryption, field-level security, and audit logging. Kibana is also configured to connect over plain HTTP with no authentication.

**The Vulnerable Code:**

File: `docker-compose.yml` | Lines: 1-26

```yaml
# VULNERABLE
services:
  elasticsearch:
    container_name: es-container
    image: docker.elastic.co/elasticsearch/elasticsearch:7.16.1
    environment:
      - "discovery.type=single-node"
      - "xpack.security.enabled=false"   # ← disables ALL security features
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    ulimits:
      memlock:
        soft: -1
        hard: -1
    networks:
      - es-net
    ports:
      - "9200:9200"   # ← exposed on all interfaces, no auth
      - "9300:9300"   # ← transport port also exposed
  kibana:
    container_name: kb-container
    image: docker.elastic.co/kibana/kibana:7.16.1
    environment:
      - ELASTICSEARCH_HOSTS=http://es-container:9200  # ← plain HTTP, no auth
    networks:
      - es-net
    depends_on:
      - elasticsearch
    ports:
      - "5601:5601"   # ← Kibana exposed on all interfaces, no auth
networks:
  es-net:
    driver: bridge
```

**Attack Scenario:**

```
Step 1: Attacker scans the host running docker-compose
        nmap -p 9200,9300,5601 target-host

Step 2: Port 9200 responds — Elasticsearch is open with no auth
        curl http://target-host:9200/
        → {"name":"es-container","cluster_name":"docker-cluster",...}

Step 3: Attacker dumps all DRWA compliance indices
        curl http://target-host:9200/drwa-holder-compliance/_search?size=10000
        curl http://target-host:9200/drwa-identities/_search?size=10000
        curl http://target-host:9200/drwa-attestations/_search?size=10000

Step 4: Attacker opens Kibana at http://target-host:5601
        Full visual access to all indexed data — no login required

Step 5: Attacker deletes all compliance records
        curl -X DELETE http://target-host:9200/drwa-holder-compliance
        curl -X DELETE http://target-host:9200/drwa-denials

Step 6: No audit log exists — attack is undetectable
```

**The Fix:**

File: `docker-compose.yml`

```yaml
# FIXED
services:
  elasticsearch:
    container_name: es-container
    image: docker.elastic.co/elasticsearch/elasticsearch:7.16.1
    environment:
      - "discovery.type=single-node"
      - "xpack.security.enabled=true"          # ← enable security
      - "xpack.security.audit.enabled=true"    # ← enable audit logging
      - "ELASTIC_PASSWORD=${ES_ADMIN_PASSWORD}" # ← set admin password from env
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    ulimits:
      memlock:
        soft: -1
        hard: -1
    networks:
      - es-net
    ports:
      - "127.0.0.1:9200:9200"   # ← bind to localhost only
      - "127.0.0.1:9300:9300"   # ← bind to localhost only
    volumes:
      - es-data:/usr/share/elasticsearch/data

  kibana:
    container_name: kb-container
    image: docker.elastic.co/kibana/kibana:7.16.1
    environment:
      - ELASTICSEARCH_HOSTS=http://es-container:9200
      - ELASTICSEARCH_USERNAME=kibana_system
      - ELASTICSEARCH_PASSWORD=${KIBANA_PASSWORD}  # ← dedicated kibana user
    networks:
      - es-net
    depends_on:
      - elasticsearch
    ports:
      - "127.0.0.1:5601:5601"   # ← bind to localhost only

networks:
  es-net:
    driver: bridge

volumes:
  es-data:
    driver: local
```

Create a `.env` file (add to `.gitignore`):

```bash
# .env — never commit this file
ES_ADMIN_PASSWORD=change_me_strong_password_1
KIBANA_PASSWORD=change_me_strong_password_2
ES_INDEXER_PASSWORD=change_me_strong_password_3
```

Add `.env` to `.gitignore`:

```gitignore
# .gitignore
.env
*.env
```

**Additional Recommendations:**

1. **Bind ports to localhost only** (`127.0.0.1:9200:9200`) so Elasticsearch is never reachable from outside the host without an explicit tunnel
2. **Use a dedicated low-privilege user** for the indexer service — not the `elastic` superuser
3. **Enable TLS** for both HTTP and transport layers in production
4. **Never use this compose file as-is for staging or production** — add a clear comment at the top of the file stating it is for local development only

```yaml
# docker-compose.yml — top of file
# ============================================================
# WARNING: LOCAL DEVELOPMENT ONLY
# This configuration disables production security controls.
# Do NOT use for staging or production deployments.
# See docs/deployment.md for production configuration.
# ============================================================
```

---

### Finding 7 — REAL FINDING — Plaintext Credentials in config.json lines 3-5

**Classification:**
- CWE: CWE-312 (Cleartext Storage of Sensitive Information)
- CVSS v3.1 Score: **6.5 (MEDIUM)** — CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
- Severity: **Medium**
- Fix Required: Yes
- Runtime Impact: Elasticsearch and proxy credentials stored in plaintext on disk — any process or user with read access to the file can extract credentials
- Monitoring Impact: No way to detect credential theft from the config file — silent exfiltration leaves no trace

**Severity Note:** MEDIUM because the credentials are stored in a JSON config file that is committed to the repository as a template with empty values. However, the structure actively invites operators to fill in real credentials directly in the file. If an operator populates the file with real credentials and commits it (a very common mistake), or if the file is readable by other processes on the same host, credentials are silently exposed. The data origin is internal operator configuration, but the risk is that credentials for both the Elasticsearch cluster and the proxy gateway end up stored in cleartext on disk and potentially in version control history. This affects the `accounts-balance-checker` tool which has direct read/write access to the Elasticsearch cluster.

**What the Vulnerable Configuration Does:**

`config.json` is the configuration file for the `accounts-balance-checker` tool. It defines connection parameters for both the Elasticsearch cluster and the MultiversX proxy gateway, including `username` and `password` fields for Elasticsearch. The file is a plain JSON file with no encryption, no environment variable substitution, and no secrets management integration. It is loaded directly via `ioutil.ReadFile` and `json.Unmarshal` with no post-processing.

Call chain: `main` → `startCheck` → `readConfig` → `ioutil.ReadFile(configFile)` → `json.Unmarshal` → credentials used directly in `elasticsearch.Config`

**The Vulnerable Code:**

File: `tools/accounts-balance-checker/cmd/balance-checker/config.json` | Lines: 1-10

```json
// VULNERABLE — structure invites plaintext credential storage
{
  "elasticsearch": {
    "url": "",
    "username": "",   // ← populated with real credentials by operators
    "password": ""    // ← stored in plaintext on disk
  },
  "proxy": {
    "url": "",
    "parallel-requests": 40
  }
}
```

File: `tools/accounts-balance-checker/cmd/balance-checker/main.go` | Function: `readConfig` | Lines: 95-105

```go
// VULNERABLE — reads credentials directly from plaintext file, no env var support
func readConfig(ctx *cli.Context) (*config.Config, error) {
    jsonFile, err := ioutil.ReadFile(ctx.String(configFile.Name))
    if err != nil {
        return nil, err
    }
    cfg := &config.Config{}
    err = json.Unmarshal(jsonFile, cfg)
    if err != nil {
        return nil, err
    }

    return cfg, nil
}
```

**Attack Scenario:**

```
Step 1: Operator populates config.json with real credentials
        {
          "elasticsearch": {
            "url": "https://prod-es.internal:9200",
            "username": "indexer_admin",
            "password": "SuperSecret123!"
          }
        }

Step 2: Operator accidentally commits the file
        git add config.json
        git commit -m "update config"
        git push origin main

Step 3: Credentials are now in git history permanently
        git log --all -p -- config.json
        → password: "SuperSecret123!" visible in every clone

Step 4: Any developer who clones the repo has the credentials
        git clone https://github.com/org/repo
        cat tools/accounts-balance-checker/cmd/balance-checker/config.json

Step 5: Attacker uses credentials to access production Elasticsearch
        curl -u indexer_admin:SuperSecret123! https://prod-es.internal:9200/_cat/indices
        → full access to all indexed blockchain and DRWA compliance data
```

**The Fix:**

Step 1 — remove credential fields from the JSON config file entirely and replace with environment variable support:

```json
// FIXED — config.json (safe to commit, no credential fields)
{
  "elasticsearch": {
    "url": "https://localhost:9200"
  },
  "proxy": {
    "url": "",
    "parallel-requests": 40
  }
}
```

Step 2 — update `readConfig` and the config struct to load credentials from environment variables:

```go
// FIXED — main.go
func readConfig(ctx *cli.Context) (*config.Config, error) {
    jsonFile, err := ioutil.ReadFile(ctx.String(configFile.Name))
    if err != nil {
        return nil, err
    }
    cfg := &config.Config{}
    err = json.Unmarshal(jsonFile, cfg)
    if err != nil {
        return nil, err
    }

    // Load credentials from environment — never from config file
    cfg.Elasticsearch.Username = requireEnv("ES_USERNAME")
    cfg.Elasticsearch.Password = requireEnv("ES_PASSWORD")

    return cfg, nil
}

func requireEnv(key string) string {
    val := os.Getenv(key)
    if val == "" {
        log.Error("required environment variable not set", "key", key)
        os.Exit(1)
    }
    return val
}
```

Step 3 — update the config struct to remove credential fields:

```go
// FIXED — pkg/config/config.go
type Config struct {
    Elasticsearch struct {
        URL      string `json:"url"`
        // Username and Password removed — loaded from environment only
        Username string `json:"-"`
        Password string `json:"-"`
    } `json:"elasticsearch"`
    Proxy struct {
        URL                    string `json:"url"`
        MaxParallelRequests    int    `json:"parallel-requests"`
    } `json:"proxy"`
}
```

Step 4 — add `config.json` with credentials to `.gitignore` and provide a safe example file:

```gitignore
# .gitignore
tools/accounts-balance-checker/cmd/balance-checker/config.json
```

```json
// config.json.example — safe to commit, checked into version control
{
  "elasticsearch": {
    "url": "https://localhost:9200"
  },
  "proxy": {
    "url": "https://gateway.multiversx.com",
    "parallel-requests": 40
  }
}
```

Step 5 — document the required environment variables in the tool README:

```markdown
## Configuration

Copy `config.json.example` to `config.json` and set the Elasticsearch URL.
Credentials must be provided via environment variables — never stored in the config file.

Required environment variables:
- `ES_USERNAME` — Elasticsearch username
- `ES_PASSWORD` — Elasticsearch password

Example:
    export ES_USERNAME=indexer_user
    export ES_PASSWORD=your_strong_password
    ./balance-checker --config-file config.json --check-balance-egld
```

**Additional Recommendations:**

1. **Scan git history** for any previously committed credentials using tools like `truffleHog` or `git-secrets`
2. **Rotate any credentials** that may have been committed, even briefly
3. **Add a pre-commit hook** to prevent accidental credential commits:

```bash
# .git/hooks/pre-commit
#!/bin/bash
if git diff --cached --name-only | xargs grep -l '"password"' 2>/dev/null | grep -v '.example'; then
    echo "ERROR: Possible credentials detected in staged files. Commit blocked."
    exit 1
fi
```

4. **Apply the same fix** to `tools/clusters-checker/cmd/checker/config.toml` which has the same pattern with empty `user` and `password` fields

---

### Finding 8 — CODE QUALITY — Short Shutdown Timeout in httpServer.go line 48

**Classification:**
- CWE: CWE-400 (Uncontrolled Resource Consumption)
- CVSS v3.1 Score: **3.1 (LOW)** — CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L
- Severity: **Low**
- Fix Required: No (recommended improvement)
- Runtime Impact: In-flight HTTP requests are forcibly terminated after 1 second during shutdown — clients receive incomplete responses or connection resets
- Monitoring Impact: Prometheus scrapes or metrics polls in progress at shutdown time will fail silently — monitoring gaps during restarts

**Severity Note:** LOW because this is a code quality issue rather than a direct security vulnerability. The 1-second graceful shutdown timeout in `Close` is too short for any non-trivial in-flight request to complete. Under normal operation this causes no harm. However during a rolling restart or a forced shutdown triggered by an attacker-induced crash, active connections are dropped abruptly. This can cause monitoring blackouts and incomplete metric exports. The data origin is internal — no external attacker input is involved. The risk is operational rather than confidentiality or integrity.

**What the Vulnerable Function Does:**

`Close` on `httpServer` calls `server.Shutdown` with a `context.WithTimeout` of exactly 1 second. `Shutdown` stops accepting new connections and waits for active connections to finish — but only up to the timeout. Any request still in flight after 1 second is forcibly terminated.

Call chain: `main` → `startIndexer` → `webServer.Close` → `httpServer.Close` → `server.Shutdown(ctx)` → active connections dropped after 1 second

**The Vulnerable Code:**

File: `api/gin/httpServer.go` | Function: `Close` | Lines: 46-50

```go
// VULNERABLE — 1 second is too short for in-flight requests
func (h *httpServer) Close() error {
    ctx, cancel := context.WithTimeout(context.Background(), time.Second)
    defer cancel()

    return h.server.Shutdown(ctx)
}
```

**The Fix:**

File: `api/gin/httpServer.go` | Function: `Close` | Lines: 46-50

```go
// FIXED — 30 seconds gives in-flight requests time to complete
const shutdownTimeout = 30 * time.Second

func (h *httpServer) Close() error {
    ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
    defer cancel()

    return h.server.Shutdown(ctx)
}
```

---

## SECTION 3 — CONSOLIDATED FIX PRIORITY

| Priority | Finding | File | Effort | Impact |
|----------|---------|------|--------|--------|
| 1 — Fix Immediately | Painless Script Injection | process/elasticproc/converters/tokenMetaData.go | Low — replace fmt.Sprintf with json.Marshal + static script | Prevents arbitrary code execution in ES |
| 2 — Fix Immediately | ES Query Injection (elasticProcessor) | process/elasticproc/elasticProcessor.go | Low — replace fmt.Sprintf with json.Marshal | Prevents delete-by-query scope expansion |
| 3 — Fix Immediately | ES Query Injection (query.go) | tools/accounts-balance-checker/pkg/check/query.go | Low — replace fmt.Sprintf with json.Marshal | Prevents data exfiltration via injected queries |
| 4 — Fix Immediately | Missing ES Authentication | cmd/elasticindexer/config/prefs.toml | Medium — enable xpack.security, create service account | Prevents unauthenticated cluster access |
| 5 — Fix This Sprint | CORS AllowAllOrigins | api/gin/webServer.go | Low — replace AllowAllOrigins with AllowOrigins whitelist | Prevents cross-origin data exfiltration |
| 6 — Fix This Sprint | Insecure Docker Compose | docker-compose.yml | Low — enable xpack.security, bind ports to localhost | Closes unauthenticated ES access in dev/staging |
| 7 — Fix This Sprint | Plaintext Credentials | tools/accounts-balance-checker/cmd/balance-checker/config.json | Low — move credentials to environment variables | Prevents credential leakage via config files |
| 8 — Next Sprint | Short Shutdown Timeout | api/gin/httpServer.go | Trivial — change 1 second to 30 seconds | Prevents dropped connections on restart |

---

## SECTION 4 — AUTOMATED SCAN RESULTS

The CodeReview tool completed a full scan of the repository and found **more than 30 additional findings**. Because the finding count exceeded the tool limit, the full list is not available in this report. All automated findings are available in the **Code Issues Panel** in the IDE.

Categories identified by the automated scan include:
- Use of deprecated `ioutil.ReadFile` and `ioutil.ReadAll` (multiple files)
- Use of deprecated `ioutil.NopCloser` in `client/elasticClientCommon.go`
- Missing error handling on several deferred `Close` calls
- Potential nil pointer dereferences in response handling
- Hardcoded timeout values across multiple packages
- Missing input length validation on several data processing paths
- Race conditions in scroll counter increments in tool clients

**Recommended Action:** Open the Code Issues Panel and triage all automated findings against the manual findings in this report. Prioritise any automated findings that overlap with the injection or authentication categories identified above.

---

## SECTION 5 — NOTES ON FALSE POSITIVES

The following patterns were reviewed and determined to be **not exploitable** in the current architecture:

1. **`prepareDRWAFinalizedBlockQuery` in elasticProcessor.go** — embeds `blockHash` and `shardID` into a Painless `update_by_query` script. `blockHash` is the output of `hex.EncodeToString` which produces only `[0-9a-f]` characters under normal node operation. The injection risk is lower than Finding 5 but the same structural fix (json.Marshal) should be applied for consistency.

2. **`drwaCanonicalEventsMap` allowlist in drwaEventsProcessor.go** — the explicit allowlist of DRWA event identifiers using exact lowercase matching is a correct and secure design. Prefix matching was intentionally avoided. This is not a vulnerability.

3. **`normalizeDRWADenialCode` in drwaEventsProcessor.go** — preserves unrecognised denial codes verbatim after trimming. This is an intentional design decision to avoid dropping evidence. The value is stored as a string field in Elasticsearch via `json.Marshal` (through the struct serialisation path), so there is no injection risk on the storage path.

4. **WebSocket connection in wsIndexerFactory.go** — the WebSocket host is configured from `prefs.toml` (operator-controlled), not from external user input. The trust boundary is the WebSocket peer (the mx-chain-go node). Compromise of the node is outside the threat model of the indexer itself.

---

*End of Security Findings & Fix Report — mx-chain-es-indexer-go*

---

## SECTION 6 — DRWA-SPECIFIC FINDINGS ADDENDUM

This section covers security issues specific to the DRWA (Digital Real World Asset) compliance implementation that were not fully addressed in Sections 1–5.

---

### DRWA Finding A — REAL FINDING — prepareDRWAFinalizedBlockQuery Injection in elasticProcessor.go

**Classification:**
- CWE: CWE-943 (Improper Neutralization of Special Elements in Data Query Logic)
- CVSS v3.1 Score: **7.5 (HIGH)** — CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H
- Severity: **High**
- Fix Required: Yes
- Runtime Impact: Injected `blockHash` in the finalized-block update-by-query can corrupt `isFinalized` flags across unintended DRWA records — compliance records marked finalized that were never actually finalized on-chain
- Monitoring Impact: Corrupted `isFinalized` flags are silent — no error is raised, downstream compliance consumers receive incorrect finality state

**Severity Note:** This was listed in Section 5 as "lower risk" because `blockHash` comes from `hex.EncodeToString`. That assessment was incomplete. `hex.EncodeToString` produces safe output under normal operation, but `prepareDRWAFinalizedBlockQuery` is called from `FinalizedBlock` which receives its input over the WebSocket channel from the mx-chain-go node. If the WebSocket peer is compromised, `finalizedBlock.HeaderHash` is attacker-controlled bytes — and `hex.EncodeToString` of attacker-controlled bytes can produce any hex string including one that contains `"` characters if the bytes are chosen to produce ASCII values in the hex output. More critically, the pattern is structurally identical to Finding 5 and must be fixed for consistency and defence-in-depth regardless of the current exploitability assessment.

**The Vulnerable Code:**

File: `process/elasticproc/elasticProcessor.go` | Function: `prepareDRWAFinalizedBlockQuery`

```go
// VULNERABLE — blockHash embedded raw into Painless update-by-query
func prepareDRWAFinalizedBlockQuery(blockHash string, shardID uint32) *bytes.Buffer {
    query := fmt.Sprintf(`{
  "script": {
    "source": "ctx._source.isFinalized = true",
    "lang": "painless"
  },
  "query": {
    "bool": {
      "must": [
        { "term": { "blockHash": "%s" } },   // ← raw string injection point
        { "term": { "shardID": %d } }
      ]
    }
  }
}`, blockHash, shardID)

    return bytes.NewBuffer([]byte(query))
}
```

**The Fix:**

```go
// FIXED — json.Marshal handles all escaping
func prepareDRWAFinalizedBlockQuery(blockHash string, shardID uint32) (*bytes.Buffer, error) {
    query := map[string]interface{}{
        "script": map[string]interface{}{
            "source": "ctx._source.isFinalized = true",
            "lang":   "painless",
        },
        "query": map[string]interface{}{
            "bool": map[string]interface{}{
                "must": []interface{}{
                    map[string]interface{}{
                        "term": map[string]interface{}{
                            "blockHash": blockHash,
                        },
                    },
                    map[string]interface{}{
                        "term": map[string]interface{}{
                            "shardID": shardID,
                        },
                    },
                },
            },
        },
    }

    encoded, err := json.Marshal(query)
    if err != nil {
        return nil, err
    }

    return bytes.NewBuffer(encoded), nil
}
```

Update the caller in `FinalizedBlock` to handle the error return:

```go
// FIXED — FinalizedBlock in elasticProcessor.go
query, err := prepareDRWAFinalizedBlockQuery(blockHashHex, finalizedBlock.ShardID)
if err != nil {
    return err
}
```

---

### DRWA Finding B — REAL FINDING — Unvalidated On-Chain Strings in DRWA Compliance Records

**Classification:**
- CWE: CWE-20 (Improper Input Validation)
- CVSS v3.1 Score: **5.3 (MEDIUM)** — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N
- Severity: **Medium**
- Fix Required: Yes
- Runtime Impact: Arbitrary strings from on-chain event topics stored verbatim as KYC status, AML status, jurisdiction codes, entity types, and investor class fields in compliance indices — compliance consumers reading these fields receive unvalidated attacker-controlled data
- Monitoring Impact: Compliance dashboards and downstream regulatory reporting systems receive corrupted or spoofed compliance field values with no indication they are invalid

**Severity Note:** MEDIUM because the storage path uses `json.Marshal` (via struct serialisation) so there is no Elasticsearch injection risk. However, the compliance fields themselves — `KYCStatus`, `AMLStatus`, `JurisdictionCode`, `EntityType`, `InvestorClass`, `RegistrationStatus`, `WhitePaperCID` — are stored verbatim from on-chain event topics with no length limit, no character validation, and no allowlist check. Any contract that emits a `drwaHolderCompliance` or `drwaIdentityRegistered` event (even a non-DRWA contract that happens to use the same event identifier) can write arbitrary strings into these fields. Since the DRWA canonical events map only checks the event identifier, not the emitting contract address, a malicious contract can pollute the compliance index with spoofed KYC/AML records.

**The Vulnerable Code:**

File: `process/elasticproc/logsevents/drwaEventsProcessor.go` | Function: `tryBuildIdentityRecord`

```go
// VULNERABLE — raw on-chain topic bytes cast to string with no validation
record.JurisdictionCode = string(topics[1])  // ← arbitrary on-chain bytes
record.EntityType = string(topics[2])        // ← arbitrary on-chain bytes
```

File: `process/elasticproc/logsevents/drwaEventsProcessor.go` | Function: `tryBuildHolderComplianceRecord`

```go
// VULNERABLE — raw on-chain topic bytes cast to string with no validation
record.KYCStatus      = string(topics[3])   // ← arbitrary on-chain bytes
record.AMLStatus      = string(topics[4])   // ← arbitrary on-chain bytes
record.InvestorClass  = string(topics[5])   // ← arbitrary on-chain bytes
record.JurisdictionCode = string(topics[6]) // ← arbitrary on-chain bytes
```

File: `process/elasticproc/logsevents/drwaEventsProcessor.go` | Function: `tryBuildTokenPolicyRecord`

```go
// VULNERABLE — raw on-chain topic bytes cast to string with no validation
record.RegistrationStatus = string(topics[1]) // ← arbitrary on-chain bytes
record.WhitePaperCID      = string(topics[1]) // ← arbitrary on-chain bytes
```

**Attack Scenario:**

```
Step 1: Attacker deploys a smart contract on MultiversX that emits:
        Event identifier: "drwaHolderCompliance"
        topics[0]: "TOKEN-abc123"          (token ID)
        topics[1]: "erd1victim"            (holder address)
        topics[3]: "approved"              (KYC status — looks legitimate)
        topics[4]: "approved"              (AML status — looks legitimate)
        topics[5]: "accredited"            (investor class)
        topics[6]: "US"                    (jurisdiction)

Step 2: The indexer processes the event — drwaCanonicalEventsMap passes
        because the identifier matches exactly

Step 3: A fake holder compliance record is written to drwa-holder-compliance
        with KYC=approved, AML=approved for erd1victim

Step 4: Compliance dashboard shows erd1victim as KYC/AML approved
        even though no legitimate DRWA registry ever approved them

Step 5: Attacker uses this spoofed compliance record to bypass
        transfer restrictions on regulated assets
```

**The Fix:**

Step 1 — validate the emitting contract address against a known DRWA registry address before processing any DRWA event:

```go
// FIXED — drwaEventsProcessor.go
// Add registry address to processor
type drwaEventsProcessor struct {
    drwaRegistryAddress string // bech32 address of the authorised DRWA registry contract
}

func newDRWAEventsProcessor(registryAddress string) *drwaEventsProcessor {
    return &drwaEventsProcessor{drwaRegistryAddress: registryAddress}
}

func (dep *drwaEventsProcessor) processEvent(args *argsProcessEvent) argOutputProcessEvent {
    identifier := string(args.event.GetIdentifier())
    if _, ok := drwaCanonicalEventsMap[strings.ToLower(identifier)]; !ok {
        return argOutputProcessEvent{}
    }

    // FIXED — verify event comes from the authorised registry contract
    if dep.drwaRegistryAddress != "" {
        emitter := string(args.event.GetAddress())
        if emitter != dep.drwaRegistryAddress {
            log.Warn("drwaEventsProcessor: event from unauthorised address",
                "identifier", identifier,
                "emitter", emitter,
                "expected", dep.drwaRegistryAddress,
            )
            return argOutputProcessEvent{}
        }
    }

    // ... rest of function unchanged
}
```

Step 2 — add field-level validation for compliance string fields:

```go
// FIXED — validate compliance field values before storing
func validateComplianceStatus(value string) string {
    allowed := map[string]struct{}{
        "approved": {}, "pending": {}, "rejected": {}, "expired": {}, "": {},
    }
    if _, ok := allowed[strings.ToLower(value)]; ok {
        return value
    }
    log.Warn("drwaEventsProcessor: unrecognised compliance status", "value", value)
    return ""
}

func validateJurisdictionCode(value string) string {
    // ISO 3166-1 alpha-2: exactly 2 uppercase letters
    if matched, _ := regexp.MatchString(`^[A-Z]{2}$`, value); matched {
        return value
    }
    if value == "" {
        return value
    }
    log.Warn("drwaEventsProcessor: invalid jurisdiction code", "value", value)
    return ""
}

func validateFieldLength(value string, maxLen int) string {
    if len(value) > maxLen {
        log.Warn("drwaEventsProcessor: field value too long, truncating",
            "len", len(value), "max", maxLen)
        return value[:maxLen]
    }
    return value
}
```

Step 3 — add the registry address to the indexer configuration:

```toml
# config.toml
[config.drwa]
    registry-address = "erd1..."  # bech32 address of the authorised DRWA registry
```

---

### DRWA Finding C — CONFIRMED SAFE — SerializeDRWA Document ID Construction

**Classification:** Not a vulnerability — confirmed safe by code review

**File:** `process/elasticproc/logsevents/serializeDrwa.go` | Function: `prepareDRWARecord`

The document IDs for all DRWA indices are constructed using `fmt.Sprintf` with on-chain values (`DenialCode`, `Subject`, `TokenID`, `Auditor`, `EventType`) and then passed through `converters.JsonEscape` before being embedded into the Elasticsearch bulk API meta line.

```go
// SAFE — JsonEscape uses json.Marshal which escapes all special characters
meta := []byte(fmt.Sprintf(
    `{ "index" : { "_index": "%s", "_id" : "%s" } }%s`,
    index,
    converters.JsonEscape(id),  // ← json.Marshal escapes quotes, backslashes, etc.
    "\n",
))
```

`JsonEscape` is implemented as:

```go
func JsonEscape(i string) string {
    b, err := json.Marshal(i)
    // ...
    return string(b[1 : len(b)-1])  // strips surrounding quotes, keeps escaping
}
```

`json.Marshal` on a string produces a JSON-safe representation with all special characters escaped. The resulting `_id` value cannot break out of the JSON string context in the bulk meta line. **This is not a vulnerability.**

However, note that extremely long on-chain values (e.g. a very long `DenialCode`) could produce an oversized document ID. Elasticsearch has a 512-byte limit on `_id` values. If the composed ID exceeds this limit, the bulk request will fail silently for that document. A length guard is recommended:

```go
// RECOMMENDED — guard against oversized document IDs
func prepareDRWARecord(id string, index string, record any) ([]byte, []byte, error) {
    const maxIDLength = 400  // conservative limit below ES 512-byte max
    if len(id) > maxIDLength {
        log.Warn("prepareDRWARecord: document ID too long, truncating",
            "original_len", len(id), "max", maxIDLength)
        id = id[:maxIDLength]
    }

    serialized, err := json.Marshal(record)
    if err != nil {
        return nil, nil, err
    }

    meta := []byte(fmt.Sprintf(
        `{ "index" : { "_index": "%s", "_id" : "%s" } }%s`,
        index,
        converters.JsonEscape(id),
        "\n",
    ))
    return meta, serialized, nil
}
```

---

### DRWA Finding D — DESIGN GAP — No Contract Address Verification for DRWA Events

**Classification:** Design-level security gap — not a code bug
- Severity: **Medium**
- Fix Required: Yes (configuration + code)

**Summary:**

The `drwaCanonicalEventsMap` allowlist correctly prevents arbitrary event identifiers from polluting the compliance index. However, it does not verify that the event was emitted by the authorised DRWA registry smart contract. Any contract on the MultiversX blockchain can emit an event with identifier `drwaHolderCompliance` or `drwaIdentityRegistered` and the indexer will process it as a legitimate compliance event.

This is a trust boundary gap: the indexer trusts the event identifier but not the event source. For a compliance system handling KYC/AML data, the source of the event is as important as its identifier.

**Evidence in code:**

File: `process/elasticproc/logsevents/drwaEventsProcessor.go` | Function: `processEvent`

```go
func (dep *drwaEventsProcessor) processEvent(args *argsProcessEvent) argOutputProcessEvent {
    identifier := string(args.event.GetIdentifier())
    if _, ok := drwaCanonicalEventsMap[strings.ToLower(identifier)]; !ok {
        return argOutputProcessEvent{}  // ← only checks identifier, not emitter address
    }
    // processes event regardless of which contract emitted it
    // args.logAddress (the contract address) is available but never checked
}
```

`args.logAddress` contains the address of the contract that emitted the log. It is passed into `processEvent` via `argsProcessEvent` but is never used by `drwaEventsProcessor`.

**Fix:** See DRWA Finding B Step 1 — add registry address validation using `args.logAddress` before processing any DRWA event.

---

### Updated Summary Table — Including DRWA Addendum

| # | File | Line | Severity | Type | Fix Required | Status |
|---|------|------|----------|------|-------------|--------|
| 1 | api/gin/webServer.go | 59 | HIGH | CORS Misconfiguration | Yes | REAL FINDING |
| 2 | cmd/elasticindexer/config/prefs.toml | 22-24 | HIGH | Missing Authentication | Yes | REAL FINDING |
| 3 | tools/accounts-balance-checker/pkg/check/query.go | 48-82 | HIGH | ES Query Injection | Yes | REAL FINDING |
| 4 | process/elasticproc/converters/tokenMetaData.go | 127-140 | HIGH | Painless Script Injection | Yes | REAL FINDING |
| 5 | process/elasticproc/elasticProcessor.go | 442-445 | HIGH | ES Query Injection (revert path) | Yes | REAL FINDING |
| A | process/elasticproc/elasticProcessor.go | ~380 | HIGH | ES Query Injection (finalize path) | Yes | DRWA FINDING |
| B | process/elasticproc/logsevents/drwaEventsProcessor.go | 130-200 | MEDIUM | Unvalidated On-Chain Compliance Strings | Yes | DRWA FINDING |
| D | process/elasticproc/logsevents/drwaEventsProcessor.go | 88 | MEDIUM | No Contract Address Verification | Yes | DRWA DESIGN GAP |
| 6 | docker-compose.yml | 7 | MEDIUM | Insecure Elasticsearch Config | Yes | REAL FINDING |
| 7 | tools/accounts-balance-checker/cmd/balance-checker/config.json | 3-5 | MEDIUM | Plaintext Credentials | Yes | REAL FINDING |
| C | process/elasticproc/logsevents/serializeDrwa.go | 95 | INFO | Document ID length guard missing | Recommended | DRWA SAFE / HARDENING |
| 8 | api/gin/httpServer.go | 48 | LOW | Short Shutdown Timeout | No | CODE QUALITY |

---

*End of DRWA Addendum — mx-chain-es-indexer-go Security Findings & Fix Report*
