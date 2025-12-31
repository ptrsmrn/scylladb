# ScyllaDB License Keypair Information

## Production Keypair (CURRENT)

**Status:** ✅ Active Production Keypair

**Seed (KEEP SECRET - backup securely!):**
```
cbe3befc0055b6f3be344e1c363f1063a116b6e5aa286340e034be082afc21db
```

**Public Key:**
```
8c58531191bdb29c0e65e3faaab347793c4fdc6314ba956eff42d36df787b6f3
```

**Generated:** 2025-12-31

**Location:** `keypair.txt` (untracked - DO NOT COMMIT TO GIT!)

## Important Notes

### ⚠️ CRITICAL: Backup the Seed Securely

The seed above MUST be backed up in multiple secure, offline locations:
- Password manager (1Password, LastPass, etc.)
- Encrypted USB drive in safe
- Printed paper in secure location
- Company secure vault/HSM

**If you lose this seed, you CANNOT generate new licenses, and you'll need to:**
1. Generate a new keypair
2. Update the embedded public key in `license_compliance.cc`
3. Rebuild and redeploy ScyllaDB to ALL customers
4. ALL existing customer licenses will become invalid

### How Licensing Works

1. **One Private Key (seed) → Unlimited Licenses**
   - Use the seed above to generate all customer licenses
   - Each license is cryptographically signed with this seed
   - Customers can verify licenses with the embedded public key

2. **Public Key is Embedded in ScyllaDB Binary**
   - The public key is obfuscated in `license_compliance.cc`
   - Cannot be used to generate licenses (only verify them)
   - Safe to distribute in open source code

3. **Generating Customer Licenses**
   ```bash
   # Unlimited license
   ./tools/scylla-license-gen.py generate-license \
     --seed cbe3befc0055b6f3be344e1c363f1063a116b6e5aa286340e034be082afc21db \
     --customer "CustomerName" \
     --unlimited \
     --output customer.key
   
   # Limited license
   ./tools/scylla-license-gen.py generate-license \
     --seed cbe3befc0055b6f3be344e1c363f1063a116b6e5aa286340e034be082afc21db \
     --customer "CustomerName" \
     --vcpus 128 \
     --storage-tb 10 \
     --expiry "2026-12-31" \
     --output customer.key
   ```

4. **Verifying a License**
   ```bash
   ./tools/scylla-license-gen.py verify-license \
     --seed cbe3befc0055b6f3be344e1c363f1063a116b6e5aa286340e034be082afc21db \
     --license-file customer.key
   ```

## Original Keypair (OBSOLETE)

The original code had placeholder test values:
```
obfuscated_pubkey_base = {
    0x8a, 0x3d, 0x7e, 0x21, 0xf4, 0x56, 0x9b, 0xc8,
    0x12, 0xe7, 0x4a, 0xbd, 0x03, 0x68, 0xdf, 0x91,
    0x5c, 0xa2, 0x37, 0xe9, 0x84, 0x1b, 0x6f, 0xc0,
    0xd5, 0x49, 0x8e, 0x22, 0xb7, 0x60, 0xf3, 0x0c
}
```

**Status:** ❌ Test values only - private key unknown
**Action:** Replaced with production keypair above

## Key Rotation (Future)

If you ever need to rotate the keypair:

### Option 1: Hard Break (Not Recommended)
1. Generate new keypair
2. Update embedded public key in code
3. Rebuild and deploy new ScyllaDB version
4. **All existing licenses become invalid**
5. Re-issue licenses to all customers

### Option 2: Multi-Key Support (Recommended)
1. Modify code to support multiple embedded public keys
2. Add new public key alongside old one
3. Old licenses continue working with old key
4. New licenses use new key
5. Gradual migration over time

## Security Considerations

1. **Seed Security:**
   - Never commit seed to git
   - Never share seed via email/Slack
   - Store in secure, access-controlled location
   - Limit access to authorized personnel only

2. **Public Key Obfuscation:**
   - XOR-based obfuscation in binary
   - Provides minimal protection (security by obscurity)
   - Determined attacker can still extract it
   - This is acceptable - public key is meant to be public!

3. **License File Protection:**
   - Customers receive `.key` files
   - Cannot generate new licenses without seed
   - Can only verify existing licenses
   - Tampering detection via Ed25519 signatures

## Example Licenses

Two example licenses are provided:

### license1.key (AcmeCorp - Unlimited)
```
SCYLLA_LICENSE:v1:AcmeCorp:0:4294967295:0
6eed593e8255f735cd4553cbb327dd28e6b8b58266d085b118127bb70925e2c54c17630754d3386432afac18a3baf4e51a730f788e04b4fc72af0ef990d9150a
```

### license2.key (BetaCo - Limited)
```
SCYLLA_LICENSE:v1:BetaCo:1798675200:64:5
0102045a6d2c988c7b06fb7229bd144e1e5c2704ba071ac577dd0e676338866782ed14c98a140ec40f644bb36e1a8a9bf305e853d26082bd4bf4210b69bacb04
```

## Questions?

Contact the ScyllaDB licensing team for assistance with:
- Generating customer licenses
- License verification issues
- Keypair rotation procedures
- Security questions

## Change Log

- **2025-12-31:** Production keypair established (seed: cbe3befc...)
- **2025-12-31:** Original test keypair replaced

