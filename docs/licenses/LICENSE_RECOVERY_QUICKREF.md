# License Recovery - Quick Reference Card

## 🚨 Problem: Write Block Deadlock

```
License expired → Grace period ended → Writes BLOCKED
But user needs to DELETE data to reduce usage!
DELETE is a write operation → Also BLOCKED?
Result: DEADLOCK! User can't recover! 💀
```

## ✅ Solution: Deletes Always Allowed

**Key Feature**: DELETE, DROP, and TRUNCATE operations work **even when writes are blocked**.

---

## Recovery Paths

### Path 1: Reduce Storage (Immediate) ✅

```bash
# Check what's exceeded
curl http://localhost:10000/v2/license/usage | jq

# Delete old data (WORKS even when writes blocked!)
cqlsh> DELETE FROM logs WHERE date < '2024-01-01';
cqlsh> DROP TABLE archived_data;
cqlsh> TRUNCATE old_logs;

# Check if back in compliance
curl http://localhost:10000/v2/license/usage | jq '.storage_limit_exceeded'
# false = Writes automatically restored!
```

### Path 2: Renew License (Permanent) ✅

```bash
# Contact ScyllaDB for new license
# Upload new license
curl -X POST http://localhost:10000/v2/license/upload \
  --data-binary @new_license.key

# Verify
curl http://localhost:10000/v2/license/status
# Status: valid, Writes restored!
```

### Path 3: Admin Override (Emergency) 🆘

```bash
# Temporary 24-hour override for critical operations
curl -X POST http://localhost:10000/v2/license/override \
  -d '{"duration_hours": 24, "reason": "emergency cleanup"}'

# Perform critical writes
cqlsh> INSERT INTO critical_data VALUES (...);

# Override expires automatically after 24h
```

---

## What Works vs What's Blocked

### ✅ ALWAYS WORKS (Even when writes blocked):

- `DELETE FROM table WHERE ...`
- `DROP TABLE ...`
- `DROP KEYSPACE ...`
- `TRUNCATE TABLE ...`
- `SELECT * FROM ...` (reads)
- License upload via API
- Status/usage queries

### ❌ BLOCKED (After grace period):

- `INSERT INTO ...`
- `UPDATE ...`
- `CREATE TABLE ...`
- `ALTER TABLE ...`
- `CREATE INDEX ...`

---

## Error Message

When writes blocked, users see:

```
ERROR: Write operation blocked

Your ScyllaDB cluster exceeded licensed limits.

Current: 60TB / Limit: 50TB (10TB over)
Grace period ended: 3 days ago

TO RESTORE WRITES:

✅ Option 1 - Delete Data (Works Now!):
  cqlsh> DELETE FROM keyspace.old_data WHERE date < '2024-01-01';
  cqlsh> DROP TABLE unused_table;
  
  Once usage drops below 50TB, writes automatically resume.

✅ Option 2 - Renew License:
  https://www.scylladb.com/contact/
  
  Upload: curl -X POST http://localhost:10000/v2/license/upload \
    --data-binary @license.key

Support: support@scylladb.com
```

---

## Implementation

### In license_service.hh:

```cpp
// Check if writes should be blocked
future<bool> is_write_blocked();

// Check if deletes are allowed (always true!)
future<bool> is_delete_allowed() {
    co_return true;  // Always allow deletes for recovery
}
```

### In storage_proxy (write path):

```cpp
future<> check_write_allowed(mutation& m) {
    // Allow deletes even when writes blocked
    if (is_delete_operation(m)) {
        co_return;  // Deletes always allowed
    }
    
    // Check if other writes blocked
    bool blocked = co_await _license_service.is_write_blocked();
    if (blocked) {
        throw write_blocked_exception(...);
    }
}
```

---

## Design Principles

### ✅ Never Create Unrecoverable State

- Users must always have a path to recover
- Deletes reduce load, never increase it
- Blocking deletes creates deadlock
- Recovery should not require external intervention

### ✅ Progressive Degradation

```
Valid License
  ↓
Expired License (Day 0-7)
  → Grace Period Active
  → All operations work
  → Warnings shown
  ↓
Grace Period Ended (Day 8+)
  → Writes blocked (INSERT, UPDATE)
  → Deletes allowed (DELETE, DROP)
  → Reads work normally
  ↓
Back in Compliance
  → Writes automatically restored!
```

### ✅ Clear Communication

- Error messages include:
  - What's exceeded (storage/vCPU)
  - By how much
  - Exact recovery steps
  - Support contact

---

## Testing

### Test: Deletes Work When Blocked

```cpp
SEASTAR_TEST_CASE(test_delete_allowed_when_writes_blocked) {
    // Setup: Grace period expired, writes blocked
    auto blocked = license_service.is_write_blocked();
    BOOST_REQUIRE(blocked);  // Writes blocked
    
    // Test: DELETE should work
    auto delete_allowed = license_service.is_delete_allowed();
    BOOST_REQUIRE(delete_allowed);  // Deletes allowed
    
    // Execute delete
    cql_execute("DELETE FROM test_table WHERE id = 1");
    // Should succeed
}
```

### Test: Writes Resume After Cleanup

```cpp
SEASTAR_TEST_CASE(test_writes_resume_after_storage_reduction) {
    // Setup: Storage 60TB, limit 50TB
    BOOST_REQUIRE(license_service.is_write_blocked());
    
    // Delete 15TB of data
    delete_old_data();  // Reduces storage to 45TB
    
    // Verify: Writes now allowed
    auto blocked = license_service.is_write_blocked();
    BOOST_REQUIRE(!blocked);  // Not blocked anymore!
}
```

---

## Monitoring

### Metrics

```
scylla_license_write_blocked = 1
scylla_license_delete_operations_while_blocked = 47
scylla_license_storage_exceeded_by_bytes = 10000000000000
scylla_license_recovery_path_available = 1
```

### Alerts

```yaml
- alert: LicenseWritesBlocked
  expr: scylla_license_write_blocked == 1
  annotations:
    summary: "Writes blocked, but deletes still work"
    instructions: |
      Users can still DELETE/DROP to reduce usage.
      Writes will resume automatically when back in compliance.
```

---

## FAQ

**Q: Why allow deletes but block inserts?**  
A: Deletes reduce usage (help compliance), inserts increase usage (hurt compliance).

**Q: Can users bypass the block?**  
A: No. The only ways out are:
1. Delete data (always works)
2. Renew license (always works)
3. Admin override (audited, time-limited)

**Q: What if user deletes too much by accident?**  
A: Writes resume immediately when back in compliance. They can re-insert if needed.

**Q: What about vCPU limits?**  
A: Can't reduce vCPUs via deletes. Options:
1. Reduce cluster size
2. Renew license
3. Admin override while waiting

**Q: Is there a risk of data loss?**  
A: No. Users explicitly choose what to delete. Reads always work for verification.

---

## Summary

### ✅ Recovery Enabled

- **DELETE always works** - Users can reduce usage
- **Writes auto-resume** - When back in compliance
- **Multiple escape hatches** - Delete, renew, or override
- **Clear instructions** - Error messages guide recovery
- **No deadlock** - Always a path forward

### 🎯 Key Benefit

**Users are never trapped.** Even with expired license and exceeded limits, they can:
1. DELETE data to get back into compliance
2. Resume normal operations automatically
3. Or renew license at any time

**No manual intervention or support ticket required for recovery!**

---

*Quick Reference Card - December 19, 2025*
*Feature: Recovery mechanisms for write blocking*

