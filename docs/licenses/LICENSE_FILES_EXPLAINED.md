# License Files - Testing Summary

## Understanding License Storage

**Important:** ScyllaDB stores **ONE active license at a time** per cluster. This is by design - a cluster operates under one license agreement.

The database table `system.licenses` has a single row with `key='current'` that holds the active license.

## Available License Files (Both Work!)

### ✅ license1.key - Unlimited License
**Customer:** AcmeCorp  
**Status:** Currently ACTIVE in database  
**Details:**
- vCPUs: Unlimited
- Storage: Unlimited
- Expiry: Never (timestamp: 0)

**File Content:**
```
SCYLLA_LICENSE:v1:AcmeCorp:0:4294967295:0
6eed593e8255f735cd4553cbb327dd28e6b8b58266d085b118127bb70925e2c54c17630754d3386432afac18a3baf4e51a730f788e04b4fc72af0ef990d9150a
```

**Verified:** ✅ Uploaded successfully, signature valid, working correctly

---

### ✅ license2.key - Limited License
**Customer:** BetaCo  
**Status:** Available (tested and working)  
**Details:**
- vCPUs: 64
- Storage: 5 TB (5497558138880 bytes)
- Expiry: 2026-12-31 (timestamp: 1798675200)

**File Content:**
```
SCYLLA_LICENSE:v1:BetaCo:1798675200:64:5
0102045a6d2c988c7b06fb7229bd144e1e5c2704ba071ac577dd0e676338866782ed14c98a140ec40f644bb36e1a8a9bf305e853d26082bd4bf4210b69bacb04
```

**Verified:** ✅ Uploaded successfully, signature valid, limits shown correctly

---

## Testing Performed

### Test 1: Upload license1.key
```bash
curl -X POST http://localhost:10000/v2/license/upload \
  -H "Content-Type: text/plain" \
  --data-binary @license1.key
```
**Result:** ✅ SUCCESS - AcmeCorp license active

**Database:**
```
 key      customer_id  expiry_timestamp
---------+-------------+------------------
 current     AcmeCorp                 0
```

---

### Test 2: Upload license2.key (replaces license1)
```bash
curl -X POST http://localhost:10000/v2/license/upload \
  -H "Content-Type: text/plain" \
  --data-binary @license2.key
```
**Result:** ✅ SUCCESS - BetaCo license active (replaced AcmeCorp)

**Database:**
```
 key      customer_id  expiry_timestamp
---------+-------------+------------------
 current       BetaCo        1798675200
```

**Usage Details:**
```json
{
  "customer_id": "BetaCo",
  "expiry_timestamp": 1798675200,
  "max_vcpus": 64,
  "max_storage_bytes": 5497558138880,
  "current_vcpus": 2,
  "current_storage_bytes": 203076,
  "vcpu_limit_exceeded": false,
  "storage_limit_exceeded": false
}
```

---

### Test 3: Re-upload license1.key (restore)
```bash
curl -X POST http://localhost:10000/v2/license/upload \
  -H "Content-Type: text/plain" \
  --data-binary @license1.key
```
**Result:** ✅ SUCCESS - AcmeCorp license active again

---

## Database State

### Current License (as of now):
```
 key      customer_id  expiry_timestamp
---------+-------------+------------------
 current     AcmeCorp                 0
```

**Only ONE row exists** - this is correct behavior!

---

## Why Only One License in Database?

**By Design:** A ScyllaDB cluster operates under **one license agreement** at a time. The licensing system:

1. ✅ Stores the current active license in `system.licenses` (one row)
2. ✅ Replicates via Raft to all nodes
3. ✅ Allows seamless license updates (upload new → replaces old)
4. ✅ No restart required

**To switch licenses:**
Simply upload a different license file - it immediately replaces the current one.

---

## How to Use Both Licenses

### For Testing Different Scenarios:

**Test Unlimited License:**
```bash
curl -X POST http://localhost:10000/v2/license/upload \
  -H "Content-Type: text/plain" \
  --data-binary @license1.key

curl http://localhost:10000/v2/license/status | jq
curl http://localhost:10000/v2/license/usage | jq
```

**Test Limited License:**
```bash
curl -X POST http://localhost:10000/v2/license/upload \
  -H "Content-Type: text/plain" \
  --data-binary @license2.key

curl http://localhost:10000/v2/license/status | jq
curl http://localhost:10000/v2/license/usage | jq
```

---

## Summary

✅ **You have 2 working example licenses:**
1. `license1.key` - Unlimited (AcmeCorp)
2. `license2.key` - Limited (BetaCo, 64 vCPUs, 5TB)

✅ **Both have been tested and verified working**

✅ **Current state:** license1.key (AcmeCorp) is active in database

✅ **Database behavior:** Only 1 license stored at a time (by design)

✅ **How to use:** Upload whichever license you want active - it replaces the previous one instantly

---

## Verification Commands

Check what's currently active:
```bash
# Quick check
curl http://localhost:10000/v2/license/status | jq

# Detailed info
curl http://localhost:10000/v2/license/usage | jq

# Database check
cqlsh -e "SELECT * FROM system.licenses;"
```

---

**Conclusion:** Both example licenses are present as files and have been verified working. The database correctly stores one active license at a time. ✅

