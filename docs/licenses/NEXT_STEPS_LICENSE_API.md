# Next Steps: License API Implementation

## ✅ Completed So Far

### 1. **API-Based License Management**
- ✅ Created `system.licenses` Raft-replicated table
- ✅ Implemented `license_service` for license storage/validation
- ✅ Created REST API endpoints:
  - `GET /v2/license/status` - Get license status
  - `POST /v2/license/upload` - Upload new license
  - `GET /v2/license/usage` - Get usage metrics
  - `DELETE /v2/license` - Delete license
- ✅ Updated compliance monitor for leader-only checks
- ✅ All files added to build system (configure.py, CMakeLists.txt)

### 2. **License Format**
- ✅ Reorganized format: `SCYLLA_LICENSE:v1:<customer>:<expiry>:<vcpus>:<storage>`
- ✅ Ed25519 asymmetric signatures
- ✅ Obfuscated public key embedded in binary

## 🚧 Next Steps

### Phase 1: Integration & Testing (IMMEDIATE)

#### 1.1 Wire Up API Endpoints in main()
**File:** `main.cc` or appropriate initialization file

```cpp
// Add to initialization:
#include "service/license_service.hh"
#include "api/license.hh"

// In main or service initialization:
sharded<service::license_service> _license_service;

// Initialize license_service
_license_service.start(
    std::ref(_abort_source),
    std::ref(_group0_client),
    std::ref(_query_processor),
    std::ref(_db)
).get();

// Register API routes
api::set_server_license(http_ctx, _license_service).get();
```

**Action:** Need to find where `set_server_client_routes` is called and add similar code for license API.

#### 1.2 Update Compliance Monitor to Use License Service
**File:** `license_compliance.cc`

Currently uses file-based licenses. Update to:
- Query `license_service.get_license()` instead of reading files
- Remove file-based logic or keep as fallback

```cpp
// In check_compliance_async():
// OLD: auto license_opt = co_await verify_license_file_async(license_path);
// NEW: Query license_service through database or pass service reference
```

#### 1.3 Write Integration Tests
**File:** `test/boost/license_api_test.cc` (NEW)

Test scenarios:
- Upload valid license via API
- Upload invalid signature (should fail)
- Upload expired license
- Check status endpoint
- Check usage endpoint
- Verify license persists across node restarts (Raft replication)
- Test leader-only compliance checking

```cpp
BOOST_AUTO_TEST_SUITE(license_api_test)

SEASTAR_TEST_CASE(test_upload_valid_license) {
    // Test uploading via API and verifying it's stored
}

SEASTAR_TEST_CASE(test_license_persists_after_restart) {
    // Verify Raft replication works
}

BOOST_AUTO_TEST_SUITE_END()
```

#### 1.4 Update Python License Tool
**File:** `tools/scylla-license-gen.py`

Add API upload capability:
```python
def cmd_upload_license_api(args):
    """Upload license via REST API instead of copying file"""
    with open(args.license_file, 'r') as f:
        content = f.read()
    
    response = requests.post(
        f"{args.api_url}/v2/license/upload",
        data=content,
        headers={'Content-Type': 'text/plain'}
    )
    
    if response.status_code == 200:
        print("License uploaded successfully")
    else:
        print(f"Failed: {response.text}")
```

### Phase 2: Compliance Monitor Enhancement

#### 2.1 Implement Performance Degradation (Optional)
**Requirement:** "implement a mechanism to degrade the performance when limits are exceeded"

Options:
1. **Artificial Delays:** Add sleep() to query processing
2. **Resource Throttling:** Reduce compaction/flush priorities
3. **Warning Only:** Just log warnings (current implementation)

**Recommendation:** Start with warnings only, add degradation as future feature.

#### 2.2 Background Check Integration
Update `compliance_monitor` to use `license_service`:

```cpp
// In compliance_monitor constructor, add license_service reference
compliance_monitor(
    seastar::abort_source& as,
    seastar::sharded<replica::database>& db,
    seastar::sharded<service::raft_group_registry>& raft_gr,
    seastar::sharded<service::license_service>& license_svc,  // NEW
    config cfg
);

// In do_check():
auto license_entry = co_await _license_svc.local().get_license();
// Use license_entry instead of file-based check
```

### Phase 3: Documentation & Operations

#### 3.1 User Documentation
**File:** `docs/operating-scylla/license-management.md` (NEW)

Document:
- How to obtain a license from ScyllaDB
- How to upload via API
- How to check license status
- What happens when limits are exceeded
- Troubleshooting

#### 3.2 Admin Scripts
**File:** `tools/scylla-license-admin.sh` (NEW)

Convenience scripts:
```bash
#!/bin/bash
# Upload license to cluster
scylla-license-admin upload --file license.key --host 192.168.1.1

# Check license status across cluster
scylla-license-admin status --host 192.168.1.1

# Show usage metrics
scylla-license-admin usage --host 192.168.1.1
```

### Phase 4: Security Hardening

#### 4.1 API Authentication
Currently API is unauthenticated. Add:
- Require admin authentication for POST/DELETE
- Allow authenticated reads for GET endpoints

#### 4.2 Audit Logging
Log all license operations:
- License uploads (who, when, what customer)
- License deletions
- License validation failures

### Phase 5: Testing & Validation

#### 5.1 Performance Testing
**Requirement:** "ensure that the licensing module doesn't degrade the performance for licensed cases"

Test scenarios:
- Benchmark with valid license vs no license
- Verify leader-only check doesn't impact other nodes
- Measure overhead of periodic checks (should be negligible)

#### 5.2 Chaos Testing
- Node failures during license upload
- Network partitions
- Concurrent license uploads
- Raft leader elections during checks

## 📋 Immediate Action Items (Priority Order)

1. **Find main.cc initialization** - Locate where services are initialized
2. **Wire up license_service** - Add to service initialization
3. **Register API endpoints** - Call `api::set_server_license()`
4. **Test basic flow:**
   ```bash
   # Generate a test license
   ./tools/scylla-license-gen.py generate-keypair
   ./tools/scylla-license-gen.py generate-license \
     --seed <seed> --customer TestCorp --unlimited
   
   # Start ScyllaDB
   ./build/dev/scylla --developer-mode 1
   
   # Upload license via API
   curl -X POST http://localhost:10000/v2/license/upload \
     -H "Content-Type: text/plain" \
     --data-binary @license.key
   
   # Check status
   curl http://localhost:10000/v2/license/status
   
   # Check usage
   curl http://localhost:10000/v2/license/usage
   ```

5. **Update compliance_monitor** - Use license_service instead of files
6. **Write integration tests** - Verify end-to-end flow
7. **Run existing tests** - Ensure nothing broke

## 🔍 Files Needing Attention

### Must Review/Update:
- `main.cc` or `init.cc` - Service initialization
- `license_compliance.cc` - Update to use license_service
- `test/boost/license_compliance_test.cc` - Update tests for API
- `configure.py` - Already updated ✅
- `CMakeLists.txt` files - Already updated ✅

### Nice to Have:
- Documentation files
- Admin scripts
- Additional test coverage

## ⚠️ Known Issues / TODOs

1. **API Authentication** - Currently no auth on endpoints
2. **License Service Initialization** - Need to wire into main()
3. **Compliance Monitor Integration** - Still uses file-based approach
4. **Test Coverage** - Need API integration tests
5. **Error Handling** - Improve error messages for users
6. **Metrics** - Add prometheus metrics for license status

## 📊 Success Criteria

- [ ] Can upload license via REST API
- [ ] License persists across node restarts (Raft)
- [ ] License automatically propagates to all nodes
- [ ] Compliance monitor uses license from system.licenses table
- [ ] Only Raft leader performs compliance checks
- [ ] All existing tests pass
- [ ] New API tests pass
- [ ] No performance degradation for licensed users
- [ ] Clear error messages when license invalid/expired

## 🎯 Final Goal

Complete, production-ready license management system that:
1. Uses tamper-proof Raft-replicated storage
2. Provides clean REST API for operations
3. Minimizes cluster overhead (leader-only checks)
4. Works seamlessly for licensed customers
5. Enforces limits for source-available users

