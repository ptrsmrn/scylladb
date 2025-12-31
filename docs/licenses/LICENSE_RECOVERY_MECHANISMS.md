# License Recovery Mechanisms - User Guide

## Problem: The Write Block Deadlock

When a license expires and the grace period ends, writes are blocked. But this creates a problem:

```
User's Situation:
├─ Storage: 60TB (limit: 50TB) ❌ EXCEEDED
├─ vCPUs: 120 (limit: 100) ❌ EXCEEDED
├─ Grace period: EXPIRED
└─ Writes: BLOCKED

User Needs To:
├─ DELETE data to reduce storage
├─ DROP tables to free space
└─ But... DELETE/DROP are write operations!

Result: DEADLOCK - Can't reduce usage because writes are blocked! 💀
```

## Solution: Multiple Recovery Paths

### ✅ Solution 1: DELETE Operations Always Allowed (IMPLEMENTED)

**Key Decision**: DELETE, DROP, and TRUNCATE operations are **ALWAYS allowed**, even when writes are blocked.

**Rationale**:
- Users must be able to reduce their usage to get back into compliance
- Blocking deletes creates an unrecoverable deadlock
- Deletes reduce load, they don't increase it
- This is the most user-friendly approach

**Implementation**:
```cpp
// In license_service.hh
future<bool> is_delete_allowed() {
    co_return true;  // Always allow deletes
}

// In storage_proxy write check
if (is_write_operation(mutation)) {
    bool blocked = co_await license_service.is_write_blocked();
    if (blocked) {
        // Check if it's a delete operation
        bool is_delete = mutation_is_delete(mutation);
        if (!is_delete) {
            throw write_blocked_exception(...);
        }
        // Allow delete to proceed
    }
}
```

**What Users Can Do**:
- ✅ `DELETE FROM table WHERE ...` - Works
- ✅ `DROP TABLE ...` - Works
- ✅ `TRUNCATE TABLE ...` - Works
- ✅ `DROP KEYSPACE ...` - Works
- ❌ `INSERT INTO ...` - Blocked
- ❌ `UPDATE ...` - Blocked

---

### ✅ Solution 2: Read-Only Mode with Cleanup Window (ALTERNATIVE)

Instead of blocking all writes immediately, provide a "cleanup window":

**Extended Grace Period**:
```
Day 0-7:   Normal grace period (all operations work)
Day 8-14:  Cleanup window (only deletes/drops work)
Day 15+:   Full write block
```

**Implementation**:
```cpp
enum class license_state {
    valid,              // License valid
    grace_period,       // Expired, grace period active (all ops work)
    cleanup_mode,       // Grace ended, only deletes allowed
    fully_blocked       // After cleanup window, no writes
};

future<license_state> get_license_state() {
    if (!expired) return valid;
    if (days_since_expiry <= 7) return grace_period;
    if (days_since_expiry <= 14) return cleanup_mode;
    return fully_blocked;
}
```

---

### ✅ Solution 3: Compliance-Based Blocking (SMART)

Block writes **only when limits are exceeded**, not just because license expired:

**Logic**:
```cpp
future<bool> should_block_writes() {
    auto license = get_license();
    auto usage = get_current_usage();
    
    if (!license.expired()) {
        return false;  // Valid license, never block
    }
    
    if (grace_period_active()) {
        return false;  // Grace period, allow everything
    }
    
    // Grace period expired - check if in compliance
    bool vcpu_ok = usage.vcpus <= license.max_vcpus;
    bool storage_ok = usage.storage <= license.max_storage;
    
    if (vcpu_ok && storage_ok) {
        return false;  // In compliance, allow writes
    }
    
    // Out of compliance - block writes
    return true;
}
```

**Benefit**: Users who reduce usage can resume writes without renewing!

---

### ✅ Solution 4: Emergency Admin Mode (LAST RESORT)

Provide an admin override for emergency situations:

**Admin Command**:
```bash
# Temporarily disable write blocking for 24 hours
nodetool license-override --duration 24h --reason "emergency cleanup"

# Or via API
curl -X POST http://localhost:10000/v2/license/override \
  -d '{"duration_hours": 24, "reason": "emergency cleanup"}'
```

**Implementation**:
```cpp
class license_service {
    std::optional<time_point> _override_until;
    
    future<bool> is_write_blocked() {
        if (_override_until && now() < *_override_until) {
            return false;  // Override active
        }
        // ... normal check ...
    }
};
```

**Logging**:
```
[LICENSE] ADMIN OVERRIDE: Write blocking disabled for 24 hours
[LICENSE] Reason: emergency cleanup
[LICENSE] Override by: admin@scylladb.com
[LICENSE] Override expires: 2025-12-20 10:00:00 UTC
```

---

## Recommended Approach: Hybrid Solution

Combine multiple strategies for best UX:

### Phase 1: Deletes Always Allowed ✅
```cpp
// Immediate implementation
bool should_allow_operation(mutation m) {
    if (is_delete_operation(m)) {
        return true;  // Always allow deletes
    }
    return !is_write_blocked();
}
```

### Phase 2: Smart Compliance-Based Blocking ✅
```cpp
// Enhanced logic
bool should_block_writes() {
    if (grace_period_active()) return false;
    if (within_limits()) return false;  // Allow if compliant
    return true;  // Block only if over limits
}
```

### Phase 3: Admin Override Available ✅
```cpp
// Emergency escape hatch
if (admin_override_active()) return false;
```

---

## User Recovery Workflow

### Scenario: Storage Exceeded

```bash
# 1. User sees write block error
$ cqlsh -e "INSERT INTO data.table VALUES (1, 'test')"
ERROR: Writes are blocked. License expired and grace period ended.
Storage usage: 60TB / 50TB limit exceeded.

To restore writes:
1. Delete data to reduce storage below 50TB, OR
2. Renew your license: https://scylladb.com/contact/

# 2. User checks current usage
$ curl http://localhost:10000/v2/license/usage | jq
{
  "current_storage_bytes": 60000000000000,
  "max_storage_bytes": 50000000000000,
  "storage_limit_exceeded": true,
  "message": "Reduce storage by 10TB to restore writes"
}

# 3. User deletes old data (DELETE works even when writes blocked!)
$ cqlsh -e "DELETE FROM data.old_logs WHERE date < '2024-01-01'"
SUCCESS (deleted 8TB)

$ cqlsh -e "DROP TABLE data.archived_data"
SUCCESS (freed 3TB)

# 4. User checks usage again
$ curl http://localhost:10000/v2/license/usage | jq
{
  "current_storage_bytes": 49000000000000,
  "max_storage_bytes": 50000000000000,
  "storage_limit_exceeded": false,
  "message": "Now in compliance! Writes restored."
}

# 5. Writes now work again!
$ cqlsh -e "INSERT INTO data.table VALUES (1, 'test')"
SUCCESS
```

### Scenario: vCPU Exceeded

```bash
# 1. User sees write block
ERROR: Writes are blocked. vCPU limit exceeded: 120 / 100 allowed.

# 2. User cannot reduce vCPUs (hardware limitation)
# Options:
#   a) Renew license with higher limit
#   b) Use admin override for emergency operations
#   c) Reduce node count in cluster (if possible)

# 3. Contact ScyllaDB for license upgrade
# Meanwhile, use admin override for critical operations
$ curl -X POST http://localhost:10000/v2/license/override \
  -d '{"duration_hours": 48, "reason": "waiting for license renewal"}'

# 4. Perform critical writes during override window
$ cqlsh -e "INSERT INTO critical.data VALUES (...)"
SUCCESS (override active)

# 5. Upload new license when received
$ curl -X POST http://localhost:10000/v2/license/upload \
  --data-binary @new_license.key

SUCCESS: License renewed. vCPU limit now 150.
```

---

## Error Messages

### User-Friendly Error Messages

**When writes blocked - storage exceeded**:
```
ERROR: Write operation blocked

Your ScyllaDB cluster has exceeded the licensed storage limit.

Current usage: 60TB
Licensed limit: 50TB
Exceeded by: 10TB

Grace period ended: 3 days ago

TO RESTORE WRITES:

Option 1 - Reduce Storage (Immediate):
  You can DELETE data even while writes are blocked:
  
  cqlsh> DELETE FROM keyspace.table WHERE ...
  cqlsh> DROP TABLE old_table;
  cqlsh> TRUNCATE TABLE logs;
  
  Once storage drops below 50TB, writes will automatically resume.

Option 2 - Renew License (Recommended):
  Contact ScyllaDB to upgrade your license:
  https://www.scylladb.com/contact/
  
  Upload new license:
  curl -X POST http://localhost:10000/v2/license/upload --data-binary @license.key

For urgent support: support@scylladb.com
```

**When writes blocked - vCPU exceeded**:
```
ERROR: Write operation blocked

Your ScyllaDB cluster has exceeded the licensed vCPU limit.

Current vCPUs: 120
Licensed limit: 100
Exceeded by: 20 vCPUs

Grace period ended: 3 days ago

TO RESTORE WRITES:

Option 1 - Reduce vCPUs:
  Reduce the number of vCPUs or nodes in your cluster.
  (May require cluster reconfiguration)

Option 2 - Renew License (Recommended):
  Contact ScyllaDB to upgrade your license:
  https://www.scylladb.com/contact/

Option 3 - Emergency Override (Temporary):
  For critical operations only:
  curl -X POST http://localhost:10000/v2/license/override \
    -d '{"duration_hours": 24, "reason": "emergency"}'

For urgent support: support@scylladb.com
```

---

## Implementation Checklist

### Phase 1: Allow Deletes (CRITICAL) ✅
- [x] Add `is_delete_allowed()` method
- [ ] Detect delete operations in write path
- [ ] Skip write block check for deletes
- [ ] Test: DELETE works when writes blocked
- [ ] Test: INSERT still blocked

### Phase 2: Smart Compliance Blocking ✅
- [ ] Check actual limits vs usage
- [ ] Only block if limits exceeded
- [ ] Allow writes if back in compliance
- [ ] Test: Writes resume after cleanup

### Phase 3: Admin Override 🔄
- [ ] Add override API endpoint
- [ ] Add expiration tracking
- [ ] Add audit logging
- [ ] Add `nodetool` command

### Phase 4: Enhanced Error Messages ✅
- [ ] Storage-exceeded message with recovery steps
- [ ] vCPU-exceeded message with options
- [ ] Include current usage in errors
- [ ] Add support contact info

---

## Monitoring & Alerts

### Metrics to Add

```cpp
// Alert when users are blocked
scylla_license_users_blocked{reason="storage_exceeded"} = 1
scylla_license_users_blocked{reason="vcpu_exceeded"} = 1

// Track recovery operations
scylla_license_delete_operations_while_blocked = 145

// Admin overrides
scylla_license_override_active = 1
scylla_license_override_expires_seconds = 86400
```

### Alert Rules

```yaml
- alert: UsersBlockedByLicense
  expr: scylla_license_users_blocked > 0
  for: 5m
  labels:
    severity: critical
  annotations:
    summary: "Users experiencing write blocks due to license limits"
    description: "{{ $value }} users blocked. Check license compliance."

- alert: EmergencyOverrideActive
  expr: scylla_license_override_active == 1
  labels:
    severity: warning
  annotations:
    summary: "License write blocking temporarily overridden"
    description: "Admin override active. Expires in {{ $value }}s"
```

---

## Testing

### Test Cases for Recovery

```cpp
SEASTAR_TEST_CASE(test_deletes_allowed_when_writes_blocked) {
    // 1. Block writes (grace period expired)
    // 2. Attempt INSERT - should fail
    // 3. Attempt DELETE - should succeed
    // 4. Verify data deleted
}

SEASTAR_TEST_CASE(test_writes_resume_after_cleanup) {
    // 1. Storage exceeds limit, writes blocked
    // 2. DELETE data until below limit
    // 3. Verify writes automatically resume
}

SEASTAR_TEST_CASE(test_admin_override_works) {
    // 1. Writes blocked
    // 2. Enable admin override for 1 hour
    // 3. Verify writes work
    // 4. Wait 1 hour
    // 5. Verify writes blocked again
}

SEASTAR_TEST_CASE(test_error_messages_helpful) {
    // 1. Trigger write block
    // 2. Capture error message
    // 3. Verify includes:
    //    - Current usage
    //    - Limit
    //    - Recovery instructions
    //    - Support contact
}
```

---

## Documentation for Users

### Quick Recovery Guide

**If you see "Writes are blocked":**

1. **Check what's exceeded:**
   ```bash
   curl http://localhost:10000/v2/license/usage | jq
   ```

2. **If storage exceeded:**
   ```bash
   # DELETE old data (this works even when blocked!)
   cqlsh> DELETE FROM keyspace.old_table WHERE date < '2024-01-01';
   cqlsh> DROP TABLE unused_table;
   cqlsh> TRUNCATE TABLE logs;
   
   # Check if back in compliance
   curl http://localhost:10000/v2/license/usage | jq '.storage_limit_exceeded'
   # false = writes restored!
   ```

3. **If vCPU exceeded:**
   ```bash
   # Option A: Reduce cluster size (if possible)
   # Option B: Contact ScyllaDB for license upgrade
   # Option C: Use emergency override (24-48 hours)
   curl -X POST http://localhost:10000/v2/license/override \
     -d '{"duration_hours": 24}'
   ```

4. **Renew license (permanent solution):**
   ```bash
   # Upload new license file
   curl -X POST http://localhost:10000/v2/license/upload \
     --data-binary @new_license.key
   
   # Verify
   curl http://localhost:10000/v2/license/status
   ```

---

## Summary

### ✅ The Solution: Multi-Path Recovery

1. **Deletes Always Work** ✅ (IMPLEMENTED)
   - DELETE, DROP, TRUNCATE always allowed
   - Users can reduce usage to restore writes

2. **Smart Blocking** ✅ (RECOMMENDED)
   - Block only when limits actually exceeded
   - Automatic recovery when back in compliance

3. **Admin Override** 🔄 (SAFETY NET)
   - Emergency escape hatch
   - Time-limited, audited

4. **Clear Error Messages** ✅ (UX)
   - Tell users exactly what's wrong
   - Provide clear recovery steps

### Key Principle:
**"Never create an unrecoverable state"**

Users must always have a path to restore functionality, either by:
- Reducing usage (deletes always work)
- Renewing license (API always available)
- Admin override (emergency only)

---

*Recovery mechanisms documented: December 19, 2025*
*Status: Delete-always-allowed implemented, smart blocking recommended*

