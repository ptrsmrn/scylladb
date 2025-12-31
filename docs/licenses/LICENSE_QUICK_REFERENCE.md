# ScyllaDB Licensing - Quick Reference Card

## 📋 Quick Commands

### Check License Status
```bash
curl http://localhost:10000/v2/license/status | jq
```

### Check Usage
```bash
curl http://localhost:10000/v2/license/usage | jq
```

### Upload License
```bash
curl -X POST http://localhost:10000/v2/license/upload \
  -H "Content-Type: text/plain" \
  --data-binary @license.key
```

---

## 🔑 Production Keypair

**Private Seed (KEEP SECRET!):**
```
cbe3befc0055b6f3be344e1c363f1063a116b6e5aa286340e034be082afc21db
```

**Public Key (in binary):**
```
8c58531191bdb29c0e65e3faaab347793c4fdc6314ba956eff42d36df787b6f3
```

---

## 🛠️ Generate Customer License

### Unlimited License
```bash
./tools/scylla-license-gen.py generate-license \
  --seed cbe3befc0055b6f3be344e1c363f1063a116b6e5aa286340e034be082afc21db \
  --customer "CompanyName" \
  --unlimited \
  --output company.key
```

### Limited License
```bash
./tools/scylla-license-gen.py generate-license \
  --seed cbe3befc0055b6f3be344e1c363f1063a116b6e5aa286340e034be082afc21db \
  --customer "CompanyName" \
  --vcpus 128 \
  --storage-tb 10 \
  --expiry "2026-12-31" \
  --output company.key
```

### Verify License
```bash
./tools/scylla-license-gen.py verify-license \
  --seed cbe3befc0055b6f3be344e1c363f1063a116b6e5aa286340e034be082afc21db \
  --license-file company.key
```

---

## 📊 License Status Values

| Status | Meaning | Action Required |
|--------|---------|----------------|
| `no_license` | No license installed | Upload license or cluster uses default limits |
| `valid` | Valid license active | None - all good ✅ |
| `grace_period` | Expired, grace period active | Renew license (7 days remaining) |
| `expired` | Grace period ended | **Writes blocked!** Upload new license immediately |

---

## ⏱️ Grace Period Timeline

```
Day 0: License expires
       ↓
Day 0-7: Grace period (cluster operates normally)
         ↓
Day 8+: Writes BLOCKED (reads still work)
```

**Grace Period Duration:** 7 days  
**After Grace Period:** Writes blocked, reads continue

---

## 📁 Test License Files

### license1.key - Unlimited (AcmeCorp)
- vCPUs: Unlimited
- Storage: Unlimited  
- Expiry: Never

### license2.key - Limited (BetaCo)
- vCPUs: 64
- Storage: 5 TB
- Expiry: 2026-12-31

### license2_expired.key - For Testing
- vCPUs: 64
- Storage: 5 TB
- Expiry: 2025-12-24 (expired)

---

## 🧪 Manual Testing

Run the grace period test script:
```bash
./test_grace_period.sh
```

This will guide you through:
1. Upload expired license
2. Check grace period status
3. Verify grace period usage
4. Restore with unlimited license
5. Verify restoration

---

## 🔒 Security Notes

✅ **Safe:**
- Public key in binary (meant to be public)
- License files sent to customers
- Open source code

❌ **SECRET:**
- Private seed (never share!)
- Only ScyllaDB team has seed
- Backup in multiple secure locations

---

## 📖 Documentation Files

| File | Purpose |
|------|---------|
| `IMPLEMENTATION_SUMMARY.md` | Complete implementation overview |
| `LICENSE_TEST_RESULTS.md` | Detailed test results (14 tests) |
| `LICENSE_UPLOAD_INSTRUCTIONS.md` | Customer guide for license upload |
| `KEYPAIR_INFO.md` | Keypair backup and management |
| `COMPLETE_TEST_SUMMARY.md` | Full test session summary |
| `test_grace_period.sh` | Manual testing script |

---

## 🚨 Emergency Procedures

### Customer Reports Expired License
1. Generate new license with extended expiry
2. Send to customer via secure channel
3. Customer uploads via API (immediate effect)
4. No restart required

### Lost Private Seed
1. ⚠️ **CRITICAL ISSUE** - Cannot generate new licenses!
2. Generate new keypair
3. Update embedded public key in code
4. Rebuild and redeploy ScyllaDB to ALL customers
5. Re-issue licenses to all customers
6. **Prevention:** Backup seed in multiple locations NOW!

### Writes Blocked After Grace Period
1. Customer must upload new valid license
2. OR reduce cluster to below default limits:
   - Default vCPUs: 4
   - Default storage: 100 GB
3. Writes resume immediately after compliance

---

## 📞 Support Contacts

For licensing issues:
- Generate customer license
- Verify license signature
- Troubleshoot upload errors
- Investigate grace period issues

**Required Information:**
- License status output
- License usage output
- ScyllaDB version
- Error messages from logs

---

## ✅ Pre-Deployment Checklist

- [ ] Private seed backed up in password manager
- [ ] Private seed stored on encrypted USB drive
- [ ] Private seed printed and stored in safe
- [ ] `keypair.txt` added to `.gitignore`
- [ ] Changes committed (excluding `keypair.txt`)
- [ ] All 14 tests passed
- [ ] Documentation reviewed
- [ ] Customer onboarding guide prepared
- [ ] Support team trained

---

**Version:** 1.0  
**Date:** 2025-12-31  
**Status:** Production Ready ✅

