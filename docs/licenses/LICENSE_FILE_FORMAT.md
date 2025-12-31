# License File Format - The Second Line Explained

## Overview

A ScyllaDB license file has **exactly 2 lines**:
```
Line 1: License data (human-readable)
Line 2: Ed25519 digital signature (128 hex characters)
```

## Real Example

### License1.key (AcmeCorp - Unlimited)
```
SCYLLA_LICENSE:v1:AcmeCorp:0:4294967295:0
6eed593e8255f735cd4553cbb327dd28e6b8b58266d085b118127bb70925e2c54c17630754d3386432afac18a3baf4e51a730f788e04b4fc72af0ef990d9150a
```

### License2.key (BetaCo - Expired)
```
SCYLLA_LICENSE:v1:BetaCo:1766534400:64:5
644f2524b245e7c5668ccc618aeebc0d46a4a349ac2be64366f2cc4692c65b78295e1de3071c0a559476e2bf358a0316533e4ca9b02f7e476026e4df988b4e0d
```

## What is the Second Line?

**The second line is an Ed25519 digital signature (128 hex characters = 64 bytes = 512 bits)**

### Breakdown

```
6eed593e8255f735cd4553cbb327dd28e6b8b58266d085b118127bb70925e2c5
4c17630754d3386432afac18a3baf4e51a730f788e04b4fc72af0ef990d9150a
└────────────────┬────────────────┘└────────────────┬────────────────┘
              64 hex chars                      64 hex chars
              = 32 bytes                        = 32 bytes
```

**Total: 128 hex characters = 64 bytes**

### What Does It Represent?

This is an **Ed25519 cryptographic signature** of the license data (line 1).

**How it's generated:**
```python
# Pseudocode
private_key = load_from_seed("cbe3befc0055b6f3be344e1c363f1063a116b6e5aa286340e034be082afc21db")
license_data = "SCYLLA_LICENSE:v1:AcmeCorp:0:4294967295:0"

signature = ed25519_sign(private_key, license_data)
# Result: 64 bytes (512 bits)

signature_hex = hex(signature)
# Result: 128 hex characters
# "6eed593e8255f735cd4553cbb327dd28e6b8b58266d085b118127bb70925e2c54c17630754d3386432afac18a3baf4e51a730f788e04b4fc72af0ef990d9150a"
```

### Why 128 Hex Characters?

Ed25519 signatures are **64 bytes long**:
- 1 byte = 2 hex characters
- 64 bytes × 2 = **128 hex characters**

This is the standard size for Ed25519 signatures (fixed length).

## How It Works

### 1. License Generation (By ScyllaDB Team)

```bash
./tools/scylla-license-gen.py generate-license \
  --seed cbe3befc0055b6f3be344e1c363f1063a116b6e5aa286340e034be082afc21db \
  --customer "AcmeCorp" \
  --unlimited \
  --output license.key
```

**Internally:**
```cpp
// From license_compliance.cc:270

seastar::sstring generate_license(
    const std::array<uint8_t, ed25519_private_key_size>& private_key,
    const license_data& data) {

    seastar::sstring license_string = data.serialize();
    // "SCYLLA_LICENSE:v1:AcmeCorp:0:4294967295:0"

    // Create signing key from the seed
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, private_key.data(), ed25519_seed_size);

    // Sign the license data
    std::array<uint8_t, ed25519_signature_size> signature;  // 64 bytes
    EVP_DigestSign(md_ctx, signature.data(), &sig_len,
                   reinterpret_cast<const unsigned char*>(license_string.data()),
                   license_string.size());

    // Convert to hex
    return license_string + "\n" + bytes_to_hex(signature.data(), signature.size());
}
```

### 2. License Verification (By ScyllaDB Server)

```cpp
// From license_compliance.cc:318

std::optional<license_data> verify_license_file(const seastar::sstring& content) {
    auto lines = split(trim(content), '\n');
    // Line 1: "SCYLLA_LICENSE:v1:AcmeCorp:0:4294967295:0"
    // Line 2: "6eed593e8255f735cd4553cbb327dd28..."
    
    seastar::sstring license_string = trim(lines[0]);
    seastar::sstring signature_hex = trim(lines[1]);
    
    // Convert hex to bytes
    auto sig_bytes = hex_to_bytes(signature_hex);  // 64 bytes
    
    // Get embedded public key
    auto pubkey = get_license_public_key();  // 32 bytes
    
    // Verify signature using Ed25519
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr, pubkey.data(), pubkey.size());
    
    int result = EVP_DigestVerify(
        md_ctx,
        sig_bytes->data(),      // 64-byte signature
        sig_bytes->size(),
        reinterpret_cast<const unsigned char*>(license_string.data()),
        license_string.size()
    );
    
    bool valid = (result == 1);  // 1 = signature valid, 0 = invalid
    
    if (!valid) {
        return std::nullopt;  // Reject license
    }
    
    return license_data::parse(license_string);
}
```

## Ed25519 Signature Details

### What is Ed25519?

Ed25519 is a **public-key signature system** with the following properties:

- **Fast:** Very quick signing and verification
- **Small:** 64-byte signatures (vs 256+ bytes for RSA)
- **Secure:** 128-bit security level (equivalent to RSA-3072)
- **Deterministic:** Same input always produces same signature

### Signature Components

The 64-byte Ed25519 signature contains:
```
Bytes 0-31:  R component (32 bytes)
Bytes 32-63: s component (32 bytes)
```

Both are part of the Ed25519 signature scheme (curve25519 math).

### Example Breakdown

For signature: `6eed593e...90d9150a`

```
R (first 32 bytes / 64 hex chars):
6eed593e8255f735cd4553cbb327dd28e6b8b58266d085b118127bb70925e2c5

s (last 32 bytes / 64 hex chars):
4c17630754d3386432afac18a3baf4e51a730f788e04b4fc72af0ef990d9150a
```

These values are derived from:
- Private key (secret)
- Message being signed (license data)
- Ed25519 signature algorithm

## Why This Format?

### Line 1: License Data (Plain Text)
**Purpose:** Human-readable, parseable by server
**Format:** `SCYLLA_LICENSE:v1:<customer>:<expiry>:<vcpus>:<storage_tb>`
**Example:** `SCYLLA_LICENSE:v1:AcmeCorp:0:4294967295:0`

**Why plain text?**
- Easy to parse and validate
- Human can read customer name, expiry, limits
- No encryption needed (signature provides integrity)

### Line 2: Digital Signature (Hex-Encoded)
**Purpose:** Prove authenticity, prevent tampering
**Format:** 128 hex characters (64 bytes)
**Example:** `6eed593e8255f735cd4553cbb327dd28...`

**Why hex encoding?**
- Text-safe (no binary data in text file)
- Easy to transmit via email, web, etc.
- Standard for cryptographic data representation

## Security Properties

### What the Signature Guarantees

1. **Authenticity**
   - Only someone with the private key can generate this signature
   - ScyllaDB can verify it came from the legitimate signer

2. **Integrity**
   - If license data is modified, signature becomes invalid
   - Even changing 1 character breaks the signature

3. **Non-repudiation**
   - Signer cannot deny creating the license
   - Cryptographic proof of authorship

### What It Does NOT Guarantee

1. **Confidentiality**
   - License data is **not encrypted** (visible in plain text)
   - Anyone can read the customer name, limits, etc.
   - This is intentional - no need to hide it

2. **Uniqueness**
   - Same input produces same signature (deterministic)
   - Not a random value each time

## Comparison with Grace Period Signature

### License Signature (Ed25519)
- **Algorithm:** Ed25519 public-key cryptography
- **Size:** 64 bytes (128 hex chars)
- **Purpose:** Verify license file authenticity
- **Signed by:** ScyllaDB team (private key)
- **Verified by:** ScyllaDB server (public key)

### Grace Period Signature (SHA-256)
- **Algorithm:** SHA-256 hash
- **Size:** 32 bytes (64 hex chars)
- **Purpose:** Prevent grace period tampering
- **Signed by:** ScyllaDB server (when grace period starts)
- **Verified by:** ScyllaDB server (on every write)

**Example:**
```
License signature (128 hex chars):
6eed593e8255f735cd4553cbb327dd28e6b8b58266d085b118127bb70925e2c5
4c17630754d3386432afac18a3baf4e51a730f788e04b4fc72af0ef990d9150a

Grace period signature (64 hex chars):
5454adc3e4fe6e31ec42f2bb5eca04aeaa442b6700c52781927555ff98571b34
```

## How to Inspect a License

### View the File
```bash
cat license.key
```

### Parse Line by Line
```bash
# Line 1: License data
head -1 license.key
# Output: SCYLLA_LICENSE:v1:AcmeCorp:0:4294967295:0

# Line 2: Signature
tail -1 license.key
# Output: 6eed593e8255f735cd4553cbb327dd28e6b8b58266d085b118127bb70925e2c5...
```

### Count Characters
```bash
# Signature should be exactly 128 hex characters
tail -1 license.key | wc -c
# Output: 129 (128 chars + newline)
```

### Verify with Tool
```bash
./tools/scylla-license-gen.py verify-license \
  --seed cbe3befc0055b6f3be344e1c363f1063a116b6e5aa286340e034be082afc21db \
  --license-file license.key
```

## Fun Facts

1. **Fixed Size**
   - Ed25519 signatures are ALWAYS 64 bytes (128 hex chars)
   - No matter how long the message is
   - Same size whether signing "Hello" or a 1GB file

2. **Fast Verification**
   - Ed25519 verification takes ~0.1ms
   - Much faster than RSA verification
   - Suitable for high-performance systems like ScyllaDB

3. **Small Keys**
   - Public key: 32 bytes (vs 256+ for RSA)
   - Private key: 32 bytes (seed) + 32 bytes (derived) = 64 bytes
   - Total keypair: 96 bytes

4. **Modern Crypto**
   - Designed in 2011 by Daniel J. Bernstein
   - Used by: SSH, Signal, Tor, cryptocurrencies
   - Considered state-of-the-art

## Summary

**The second line of a license file is:**

✅ An **Ed25519 digital signature** (64 bytes)  
✅ Encoded as **128 hexadecimal characters**  
✅ Generated by **signing line 1 with the private key**  
✅ Verified by **ScyllaDB server with the embedded public key**  
✅ Provides **authenticity and integrity** (not encryption)  
✅ Fixed length, regardless of license data size  

**Purpose:** Prove that the license was issued by ScyllaDB and hasn't been tampered with.

**Format:**
```
Line 1: SCYLLA_LICENSE:v1:<customer>:<expiry>:<vcpus>:<storage_tb>
Line 2: <128 hex characters = Ed25519 signature of line 1>
```

**Example:**
```
SCYLLA_LICENSE:v1:AcmeCorp:0:4294967295:0
6eed593e8255f735cd4553cbb327dd28e6b8b58266d085b118127bb70925e2c54c17630754d3386432afac18a3baf4e51a730f788e04b4fc72af0ef990d9150a
└──────────────────┬──────────────────┘
              License data
└──────────────────────────────────────────────────────────────────────────────────┬──────────────────────────────────────────────────────────────────────────────────┘
                                                                               Ed25519 signature (128 hex chars = 64 bytes)
```

That huge hex string is what makes your license tamper-proof! 🔐

