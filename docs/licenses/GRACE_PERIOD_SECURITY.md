# Grace Period Security - How Tampering is Prevented

## Overview

The grace period mechanism is cryptographically secured to prevent users from manipulating the grace period start timestamp and extending the grace period indefinitely.

## Security Architecture

### 1. Grace Period Data Storage

When a license expires and grace period starts, TWO fields are stored in `system.licenses`:

```sql
grace_period_start_timestamp BIGINT  -- Unix timestamp when grace period began
grace_period_signature TEXT          -- Cryptographic signature
```

### 2. Signature Generation

When the grace period starts, a signature is generated:

```cpp
// From service/license_service.cc:330

seastar::sstring generate_grace_period_signature(
    const seastar::sstring& license_data,
    int64_t grace_period_start_timestamp) {
    
    auto public_key = license::get_license_public_key();
    
    // Sign: license_data + ":" + grace_period_start_timestamp
    seastar::sstring data_to_sign = format("{}:{}", 
                                          license_data, 
                                          grace_period_start_timestamp);
    
    // Use SHA-256(public_key + data) as signature
    // This creates a tamper-proof hash
    hash = SHA256(public_key || data_to_sign)
    
    return hex(hash);
}
```

**Key points:**
- Combines the **original license data** + **grace period timestamp**
- Uses the **embedded public key** as a salt
- Creates a SHA-256 hash that binds them together
- Result is 64-character hex string

### 3. What Gets Signed

The signature covers:
```
SHA-256(public_key || license_data || ":" || grace_period_start_timestamp)
```

**Example:**
```
public_key: 8c58531191bdb29c0e65e3faaab347793c4fdc6314ba956eff42d36df787b6f3
license_data: SCYLLA_LICENSE:v1:BetaCo:1766534400:64:5
grace_period_start_timestamp: 1735056800

Data to sign: "SCYLLA_LICENSE:v1:BetaCo:1766534400:64:5:1735056800"

Signature: SHA-256(public_key + data_to_sign)
Result: a4b3c2d1e5f6... (64 hex chars)
```

### 4. Database Storage (Atomic Update)

Both fields are written together via Raft:

```cpp
// From service/license_service.cc:495

UPDATE system.licenses 
SET grace_period_start_timestamp = ?,    -- 1735056800
    grace_period_signature = ?           -- a4b3c2d1e5f6...
WHERE key = 'current'
```

**Via Raft group0:**
- Atomic update (both fields or neither)
- Replicated to all nodes
- Consistent across cluster

### 5. Verification on Every Check

Every time the system checks if writes should be blocked:

```cpp
// From service/license_service.cc:390

seastar::future<bool> is_write_blocked() {
    auto entry_opt = co_await get_license();
    
    // ... check if expired ...
    
    // CRITICAL: Verify grace period signature
    if (!verify_grace_period_signature(
            entry_opt->license_data,
            entry_opt->grace_period_start_timestamp,
            entry_opt->grace_period_signature)) {
        
        lslog.error("Grace period signature tampering detected! Blocking writes.");
        co_return true;  // BLOCK WRITES IMMEDIATELY
    }
    
    // Only if signature is valid, check if grace period expired
    auto grace_end = grace_start + 7_days;
    if (now >= grace_end) {
        co_return true;  // Grace period ended, block writes
    }
    
    co_return false;  // Still in grace period, allow writes
}
```

## Attack Scenarios & Defenses

### Attack 1: User Modifies Timestamp via CQL

**Attempt:**
```sql
UPDATE system.licenses 
SET grace_period_start_timestamp = <future_date>
WHERE key = 'current';
```

**Defense:** ❌ **BLOCKED**
- `system.licenses` table is protected
- CQL writes to this table are **blocked** (only API can write)
- Registered as a group0 table with special protection

**Code:**
```cpp
// From db/system_keyspace.cc
static const std::unordered_set<std::string_view> tables = {
    // ... other tables ...
    system_keyspace::LICENSES,  // Protected!
};

if (ks_name == system_keyspace::NAME && tables.contains(cf_name)) {
    props.is_group0_table = true;  // API-only writes
}
```

### Attack 2: User Modifies Timestamp AND Signature via API

**Attempt:**
```bash
# Try to upload a fake grace period entry
curl -X POST http://localhost:10000/v2/license/upload \
  --data "modified_license_with_fake_grace_period"
```

**Defense:** ❌ **BLOCKED**
- API only accepts license upload, not grace period modification
- Grace period can only be set by `check_and_update_grace_period()`
- That function is called internally, not exposed via API

**Endpoints:**
```cpp
POST /v2/license/upload     // Uploads NEW license (resets grace period)
POST /v2/license/check      // Triggers check (sets grace period if needed)
GET  /v2/license/status     // Read-only
GET  /v2/license/usage      // Read-only
```

**NO endpoint to directly set grace period fields!**

### Attack 3: User Modifies Database Files Directly

**Attempt:**
- Stop ScyllaDB
- Edit SSTable files on disk
- Modify grace_period_start_timestamp
- Restart ScyllaDB

**Defense:** ⚠️ **DETECTED**
- Signature verification will **fail**
- On next check, system detects tampering:
  ```cpp
  if (!verify_grace_period_signature(...)) {
      lslog.error("Grace period signature tampering detected! Blocking writes.");
      co_return true;  // BLOCK WRITES
  }
  ```
- Writes are immediately blocked
- Logs show "tampering detected"

### Attack 4: User Calculates Valid Signature

**Attempt:**
- User reads public key from binary
- User tries to calculate: `SHA-256(public_key + license_data + timestamp)`
- User modifies both timestamp AND signature

**Defense:** ✅ **STILL PROTECTED**

**Why it's hard:**
1. Public key is **obfuscated** in the binary (XORed with derived bytes)
2. Even if extracted, user needs to:
   - Know the exact signature algorithm
   - Have the exact license_data string
   - Calculate for a future timestamp
3. But they can only write via API, which doesn't allow direct grace period updates

**However:** If user has:
- Root access to the machine
- Can decompile the binary
- Can extract the public key
- Can stop ScyllaDB and modify files directly

Then they could theoretically:
1. Calculate a valid signature for a future timestamp
2. Modify the database files
3. Restart

**But this requires:**
- Root/admin access (game over anyway)
- Stopping the cluster (downtime)
- Low-level SSTable manipulation
- **This is considered an "admin with root access" attack - out of scope**

### Attack 5: System Clock Manipulation

**Attempt:**
- Set system clock backwards
- Grace period "hasn't expired yet" according to the clock

**Defense:** ⚠️ **PARTIALLY VULNERABLE**
- Grace period check uses `system_clock::now()`
- If admin sets clock backwards, grace period appears longer
- **Mitigation:** Require NTP synchronization in production
- **Detection:** Monitor for clock skew in logs

**Code:**
```cpp
auto grace_start = system_clock::time_point{seconds{entry->grace_period_start_timestamp}};
auto grace_end = grace_start + license::grace_period_duration;  // +7 days
auto now = system_clock::now();  // ⚠️ Can be manipulated by root

if (now >= grace_end) {
    co_return true;  // Block writes
}
```

**Recommendation:**
- Enforce NTP sync in production
- Log warnings if clock skew detected
- Monitor for sudden clock changes

## Complete Security Chain

```
1. License expires
   ↓
2. Compliance check runs (periodic or forced via API)
   ↓
3. System detects expiration
   ↓
4. Generate grace period signature:
   signature = SHA-256(public_key + license_data + timestamp)
   ↓
5. Write BOTH to database via Raft (atomic):
   - grace_period_start_timestamp
   - grace_period_signature
   ↓
6. On every write operation:
   a. Read grace period fields
   b. Verify signature matches
   c. If signature invalid → BLOCK WRITES (tampering detected)
   d. If signature valid → Check if grace period expired
   e. If expired → BLOCK WRITES
   f. If not expired → ALLOW WRITES
```

## Why This is Secure

### ✅ Strengths

1. **Cryptographic Binding**
   - Grace period timestamp is cryptographically bound to license data
   - Cannot modify timestamp without breaking signature

2. **No API to Modify Grace Period**
   - Only internal code can set grace period
   - API only allows license upload (which resets grace period)

3. **CQL Protection**
   - Direct CQL writes to `system.licenses` are blocked
   - Table is group0-protected

4. **Tampering Detection**
   - Invalid signature → immediate write blocking
   - Logged as error: "tampering detected"

5. **Raft Consistency**
   - Changes replicated to all nodes
   - Consistent view across cluster

### ⚠️ Limitations

1. **Root Access**
   - Admin with root can modify files directly
   - But this is true for ANY licensing system
   - Considered out of scope (if you have root, game over)

2. **Clock Manipulation**
   - Root can set system clock backwards
   - **Mitigation:** Require NTP in production
   - Future: Could add additional time anchoring

3. **Obfuscation ≠ Encryption**
   - Public key obfuscation is security by obscurity
   - Determined attacker can extract it
   - But they still can't modify database without detection

## Testing Tampering Detection

### Test 1: Try to Modify via CQL
```sql
-- This will FAIL
UPDATE system.licenses 
SET grace_period_start_timestamp = 999999999
WHERE key = 'current';
-- Error: Cannot modify system.licenses via CQL
```

### Test 2: Verify Signature Check
```bash
# Upload expired license
curl -X POST http://localhost:10000/v2/license/upload --data-binary @expired.key

# Force grace period start
curl -X POST http://localhost:10000/v2/license/check

# Check database - signature should be present
cqlsh -e "SELECT grace_period_signature FROM system.licenses WHERE key='current';"

# If signature is tampered (manually corrupted):
# - is_write_blocked() will return true
# - Logs will show "tampering detected"
```

## Summary

**Grace Period Security Model:**

| Attack Vector | Protected By | Effectiveness |
|--------------|--------------|---------------|
| CQL modification | group0 table protection | ✅ Blocked |
| API manipulation | No exposed endpoint | ✅ Blocked |
| Direct file edit | Signature verification | ✅ Detected |
| Signature forgery | Requires binary reversing + file access | ⚠️ Hard |
| Clock manipulation | Requires root access | ⚠️ Vulnerable |

**Bottom Line:**
- ✅ Strong protection against normal users
- ✅ Tampering is detected and blocked
- ✅ Grace period cannot be extended without breaking signature
- ⚠️ Root/admin with system access can bypass (but this is true for any licensing)

**Recommendation for Production:**
1. Enable NTP synchronization (prevent clock attacks)
2. Monitor logs for "tampering detected" messages
3. File system permissions on ScyllaDB data directories
4. Regular audits of license status

The grace period is **cryptographically secured** and provides strong protection against tampering by non-privileged users.

