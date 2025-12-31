# Quick Reference: License API Implementation

## What We Built

### Architecture Overview
```
┌─────────────────────────────────────────────────────────────┐
│                    REST API Layer                           │
│  GET  /v2/license/status  - Check license status           │
│  POST /v2/license/upload  - Upload new license             │
│  GET  /v2/license/usage   - View usage metrics             │
│  DELETE /v2/license       - Delete license                 │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│              service::license_service                       │
│  - upload_license()    - Verify signature & store          │
│  - get_status()        - Return valid/expired/invalid      │
│  - get_usage()         - Compare usage vs limits           │
│  - verify_license()    - Ed25519 signature check           │
└───────────────────────────────────────────���─────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│         system.licenses (Raft-replicated table)             │
│  key (PK)         | 'current'                               │
│  license_data     | 'SCYLLA_LICENSE:v1:...'                 │
│  signature        | 'hex-encoded Ed25519 signature'         │
│  uploaded_at      | timestamp                               │
│  customer_id      | extracted customer ID                   │
│  expiry_timestamp | extracted expiry (0 = never)            │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│          compliance_monitor (leader-only checks)            │
│  - Runs on Raft group0 leader only                         │
│  - Checks every 1 hour (configurable)                      │
│  - Logs warnings when limits exceeded                      │
│  - Uses license_service to get current license             │
└─────────────────────────────────────────────────────────────┘
```

## Key Design Decisions

### 1. **Raft-Replicated Storage** ✅
- **Why:** Tamper-proof, cluster-wide consistency
- **Table:** `system.licenses` 
- **Benefit:** License automatically propagates to all nodes
- **Security:** Not accessible via CQL, only through API

### 2. **Leader-Only Compliance Checks** ✅
- **Why:** Minimize cluster overhead
- **How:** Check `raft_group_registry.group0().is_leader()`
- **Frequency:** Every 1 hour (configurable)
- **Benefit:** N nodes → 1 check instead of N checks

### 3. **Ed25519 Asymmetric Signatures** ✅
- **Why:** Customers can't forge licenses
- **Public Key:** Obfuscated in scylla binary
- **Private Key:** Kept secure by ScyllaDB (for license generation)
- **Verification:** Fast (~microseconds)

### 4. **API-First Approach** ✅
- **Why:** Better UX, no manual file distribution
- **Endpoints:** RESTful design following existing patterns
- **Format:** Plain text (license_data\nsignature)

## File Structure

```
/home/piotrsmaron/src/scylla_sa_license/
├── db/
│   ├── system_keyspace.hh          # Added LICENSES constant
│   └── system_keyspace.cc          # Added licenses() schema
├── service/
│   ├── license_service.hh          # ⭐ NEW - Service interface
│   └── license_service.cc          # ⭐ NEW - Service implementation
├── api/
│   ├── license.hh                  # ⭐ NEW - API declarations
│   ├── license.cc                  # ⭐ NEW - API handlers
│   └── api-doc/license.json        # ⭐ NEW - Swagger definition
├── license_compliance.hh           # Updated with API support
├── license_compliance.cc           # Updated with API support
├── tools/
│   └── scylla-license-gen.py       # License generation tool
└── test/boost/
    └── license_compliance_test.cc  # Existing tests (all pass ✅)
```

## Testing the Implementation

### 1. Generate a Test License
```bash
cd /home/piotrsmaron/src/scylla_sa_license

# Generate keypair (one-time)
./tools/scylla-license-gen.py generate-keypair > keypair.txt

# Extract seed from output
SEED="<seed from keypair.txt>"

# Generate unlimited license for testing
./tools/scylla-license-gen.py generate-license \
  --seed "$SEED" \
  --customer "TestCorp" \
  --unlimited \
  --output test_license.key

# View license details
cat test_license.key
```

### 2. Start ScyllaDB (Once Wired Up)
```bash
./build/dev/scylla --developer-mode 1
```

### 3. Upload License via API
```bash
# Upload license
curl -X POST http://localhost:10000/v2/license/upload \
  -H "Content-Type: text/plain" \
  --data-binary @test_license.key

# Should return 200 OK
```

### 4. Check License Status
```bash
# Get status
curl http://localhost:10000/v2/license/status | jq

# Expected response:
# {
#   "status": "valid",
#   "customer_id": "TestCorp",
#   "message": null
# }
```

### 5. Check Usage
```bash
# Get usage metrics
curl http://localhost:10000/v2/license/usage | jq

# Expected response:
# {
#   "customer_id": "TestCorp",
#   "expiry_timestamp": 0,
#   "max_vcpus": null,  # unlimited
#   "max_storage_bytes": null,  # unlimited
#   "current_vcpus": 8,
#   "current_storage_bytes": 1073741824,
#   "vcpu_limit_exceeded": false,
#   "storage_limit_exceeded": false
# }
```

### 6. Run Unit Tests
```bash
# Run license compliance tests
./test.py --mode=dev test/boost/license_compliance_test.cc

# All 19 tests should pass ✅
```

## What's NOT Done Yet

### Critical (Must Do Before Production):
1. **Service Initialization** - Wire `license_service` into main()
2. **API Registration** - Call `api::set_server_license()`
3. **Compliance Monitor Integration** - Use license_service instead of files
4. **Integration Tests** - API upload → storage → retrieval flow

### Important (Should Do):
1. **API Authentication** - Require admin role for POST/DELETE
2. **Audit Logging** - Log all license operations
3. **Documentation** - User guide for license management
4. **Error Messages** - User-friendly error responses

### Nice to Have:
1. **Admin Scripts** - CLI wrappers for API operations
2. **Prometheus Metrics** - License status metrics
3. **Performance Degradation** - Optional throttling when limits exceeded
4. **Multi-license Support** - Multiple customers per cluster (future)

## Quick Wins (Do These First)

### 1. Find Service Initialization Location
```bash
# Search for where client_routes_service is initialized
grep -r "client_routes_service.*start" . --include="*.cc"

# Add similar initialization for license_service
```

### 2. Test Existing Functionality
```bash
# Verify all existing tests still pass
./test.py --mode=dev test/boost/license_compliance_test.cc

# Expected: 19 passed
```

### 3. Manual API Test
Once wired up, test the full flow:
- Generate license
- Upload via API
- Query status
- Restart node
- Verify license persists (Raft)

## Debugging Tips

### Check License in Database
```cql
# Once ScyllaDB running with license uploaded:
SELECT * FROM system.licenses;

# Should show:
# key='current', license_data='SCYLLA_LICENSE:v1:...', signature='...'
```

### Check Compliance Monitor
```bash
# Look for log messages:
grep -i "license" scylladb.log

# Should see:
# - "License uploaded successfully for customer 'X'"
# - "License compliance check: licensed customer 'X'"
# - "License compliance check: running on leader node"
```

### Verify Leader-Only Checks
```bash
# In multi-node cluster, only leader should log compliance checks
# On leader node:
grep "License compliance check: running on leader" scylladb.log

# On follower nodes:
grep "License check skipped: not the Raft group0 leader" scylladb.log
```

## Performance Characteristics

### Expected Overhead:
- **License Upload:** ~1ms (one-time operation)
- **Signature Verification:** ~0.1ms (Ed25519 is fast)
- **Compliance Check:** ~10ms (leader only, every 1 hour)
- **Storage:** ~500 bytes per license (negligible)
- **Network:** No impact (Raft handles replication)

### Scalability:
- **Cluster Size:** No impact (leader-only checks)
- **Request Rate:** No impact (checks are periodic, not per-request)
- **Storage Growth:** Static (single row in system.licenses)

## Summary

**Status:** ✅ Core implementation complete and compiling

**Ready For:**
- Service initialization wiring
- API endpoint registration  
- Integration testing
- Production hardening

**Next Action:** Wire up `license_service` in main initialization code (see NEXT_STEPS_LICENSE_API.md)


