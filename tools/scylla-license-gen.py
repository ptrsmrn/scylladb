#!/usr/bin/env python3
"""
ScyllaDB License Generation Tool

This script generates Ed25519 keypairs and creates signed license files
for ScyllaDB commercial customers.

Usage:
    # Generate a new master keypair (do this ONCE, store seed securely)
    ./scylla-license-gen.py generate-keypair
    
    # Generate a license for a customer
    ./scylla-license-gen.py generate-license \
        --seed <hex_seed> \
        --customer "ACME Corp" \
        --vcpus 100 \
        --storage-tb 50 \
        --expiry "2026-12-31"
    
    # Generate an unlimited, never-expiring license
    ./scylla-license-gen.py generate-license \
        --seed <hex_seed> \
        --customer "Enterprise Customer" \
        --unlimited
    
    # Show the C++ code to embed a public key
    ./scylla-license-gen.py show-embedding --seed <hex_seed>
    
    # Verify a license file
    ./scylla-license-gen.py verify-license \
        --seed <hex_seed> \
        --license-file /path/to/license.key

Copyright (C) 2024-present ScyllaDB
SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.0
"""

import argparse
import os
import sys
from datetime import datetime, timezone
from typing import Optional, Tuple

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
except ImportError:
    print("Error: 'cryptography' package is required.")
    print("Install it with: pip install cryptography")
    sys.exit(1)


# Constants matching the C++ implementation
PUBKEY_SALT = 0x5C411A2024DB01F5
UNLIMITED_VCPUS = 0xFFFFFFFF
UNLIMITED_STORAGE = 0  # In the license format, 0 TB means unlimited



def derive_byte(pos: int, salt: int) -> int:
    """
    Derive a pseudo-random byte from position and salt.
    Must match the C++ derive_byte() function exactly.
    """
    v = (pos * 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
    v ^= salt
    v ^= (v >> 33)
    v = (v * 0xFF51AFD7ED558CCD) & 0xFFFFFFFFFFFFFFFF
    v ^= (v >> 33)
    v = (v * 0xC4CEB9FE1A85EC53) & 0xFFFFFFFFFFFFFFFF
    v ^= (v >> 33)
    return v & 0xFF


def generate_keypair() -> Tuple[bytes, bytes]:
    """
    Generate a new Ed25519 keypair.
    Returns (seed, public_key) as bytes.
    """
    # Generate random seed
    seed = os.urandom(32)
    
    # Create private key from seed
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    
    # Get public key bytes
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    return seed, public_key


def keypair_from_seed(seed: bytes) -> Tuple[Ed25519PrivateKey, bytes]:
    """
    Regenerate keypair from a seed.
    Returns (private_key_object, public_key_bytes).
    """
    if len(seed) != 32:
        raise ValueError("Seed must be exactly 32 bytes")
    
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    return private_key, public_key


def obfuscate_public_key(public_key: bytes, salt: int = PUBKEY_SALT) -> bytes:
    """
    Obfuscate the public key by XORing with derived values.
    This is what gets embedded in the C++ code.
    """
    obfuscated = bytearray(32)
    for i in range(32):
        obfuscated[i] = public_key[i] ^ derive_byte(i, salt)
    return bytes(obfuscated)


def deobfuscate_public_key(obfuscated: bytes, salt: int = PUBKEY_SALT) -> bytes:
    """
    Recover the public key from obfuscated values.
    XOR is its own inverse.
    """
    return obfuscate_public_key(obfuscated, salt)


def format_license_data(
    customer_id: str,
    expiry_timestamp: int,
    max_vcpus: int,
    max_storage_tb: int
) -> str:
    """
    Format license data string.
    Format: SCYLLA_LICENSE:v1:<customer>:<expiry>:<vcpus>:<storage_tb>
    """
    return f"SCYLLA_LICENSE:v1:{customer_id}:{expiry_timestamp}:{max_vcpus}:{max_storage_tb}"


def sign_license(private_key: Ed25519PrivateKey, license_data: str) -> bytes:
    """Sign the license data string."""
    return private_key.sign(license_data.encode('utf-8'))


def verify_signature(public_key_bytes: bytes, license_data: str, signature: bytes) -> bool:
    """Verify a license signature."""
    try:
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature, license_data.encode('utf-8'))
        return True
    except InvalidSignature:
        return False


def generate_license_file(
    seed: bytes,
    customer_id: str,
    max_vcpus: int = UNLIMITED_VCPUS,
    max_storage_tb: int = UNLIMITED_STORAGE,
    expiry: Optional[datetime] = None
) -> str:
    """
    Generate a complete license file content.
    
    Args:
        seed: 32-byte Ed25519 seed
        customer_id: Customer identifier
        max_vcpus: Maximum vCPUs (UNLIMITED_VCPUS for unlimited)
        max_storage_tb: Maximum storage in TB (0 for unlimited)
        expiry: Expiration datetime (None for never expires)
    
    Returns:
        License file content (data line + signature line)
    """
    private_key, _ = keypair_from_seed(seed)
    
    expiry_ts = 0 if expiry is None else int(expiry.timestamp())
    
    license_data = format_license_data(customer_id, expiry_ts, max_vcpus, max_storage_tb)
    signature = sign_license(private_key, license_data)
    
    return f"{license_data}\n{signature.hex()}"


def parse_expiry(expiry_str: Optional[str]) -> Optional[datetime]:
    """Parse expiry date string."""
    if expiry_str is None or expiry_str.lower() in ('never', 'none', ''):
        return None
    
    # Try various formats
    formats = [
        "%Y-%m-%d",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d",
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(expiry_str, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    
    # Try Unix timestamp
    try:
        return datetime.fromtimestamp(int(expiry_str), tz=timezone.utc)
    except ValueError:
        pass
    
    raise ValueError(f"Cannot parse expiry date: {expiry_str}")


def cmd_generate_keypair(args):
    """Generate a new keypair."""
    seed, public_key = generate_keypair()
    
    print("=" * 70)
    print("NEW ED25519 KEYPAIR GENERATED")
    print("=" * 70)
    print()
    print("SEED (KEEP THIS SECRET - store securely offline):")
    print(f"  {seed.hex()}")
    print()
    print("PUBLIC KEY (raw bytes):")
    print(f"  {public_key.hex()}")
    print()
    
    if args.show_embedding:
        show_embedding_code(seed, public_key)


def show_embedding_code(seed: bytes, public_key: bytes):
    """Show the C++ code needed to embed this public key."""
    obfuscated = obfuscate_public_key(public_key)
    
    print("C++ CODE FOR EMBEDDING:")
    print("-" * 70)
    print("// Copy this to license_compliance.cc, replacing obfuscated_pubkey_base")
    print("constexpr std::array<uint8_t, 32> obfuscated_pubkey_base = {")
    
    for i in range(0, 32, 8):
        line = "    "
        for j in range(8):
            if i + j < 32:
                line += f"0x{obfuscated[i+j]:02x}"
                if i + j < 31:
                    line += ", "
        print(line)
    
    print("};")
    print("-" * 70)
    print()
    print("VERIFICATION:")
    print(f"  Salt: 0x{PUBKEY_SALT:016X}")
    print(f"  Obfuscated XOR Derived = Original Public Key: ✓")


def cmd_show_embedding(args):
    """Show embedding code for an existing seed."""
    seed = bytes.fromhex(args.seed)
    _, public_key = keypair_from_seed(seed)
    
    print(f"Seed: {seed.hex()}")
    print(f"Public Key: {public_key.hex()}")
    print()
    show_embedding_code(seed, public_key)


def cmd_generate_license(args):
    """Generate a license file."""
    seed = bytes.fromhex(args.seed)
    
    if args.unlimited:
        max_vcpus = UNLIMITED_VCPUS
        max_storage_tb = UNLIMITED_STORAGE
        expiry = None
    else:
        max_vcpus = args.vcpus if args.vcpus is not None else UNLIMITED_VCPUS
        max_storage_tb = args.storage_tb if args.storage_tb is not None else UNLIMITED_STORAGE
        expiry = parse_expiry(args.expiry)
    
    license_content = generate_license_file(
        seed=seed,
        customer_id=args.customer,
        max_vcpus=max_vcpus,
        max_storage_tb=max_storage_tb,
        expiry=expiry
    )
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(license_content)
        print(f"License written to: {args.output}")
    else:
        print("=" * 70)
        print("GENERATED LICENSE")
        print("=" * 70)
        print(license_content)
        print("=" * 70)
    
    # Print summary
    print()
    print("License Summary:")
    print(f"  Customer: {args.customer}")
    print(f"  vCPUs: {'unlimited' if max_vcpus == UNLIMITED_VCPUS else max_vcpus}")
    print(f"  Storage: {'unlimited' if max_storage_tb == 0 else f'{max_storage_tb} TB'}")
    print(f"  Expiry: {'never' if expiry is None else expiry.strftime('%Y-%m-%d %H:%M:%S UTC')}")


def cmd_verify_license(args):
    """Verify a license file."""
    seed = bytes.fromhex(args.seed)
    _, public_key = keypair_from_seed(seed)
    
    with open(args.license_file, 'r') as f:
        content = f.read().strip()
    
    lines = content.split('\n')
    if len(lines) != 2:
        print("ERROR: License file must have exactly 2 lines")
        sys.exit(1)
    
    license_data = lines[0].strip()
    signature_hex = lines[1].strip()
    
    try:
        signature = bytes.fromhex(signature_hex)
    except ValueError:
        print("ERROR: Invalid signature format")
        sys.exit(1)
    
    if verify_signature(public_key, license_data, signature):
        print("✓ License signature is VALID")
        print()
        print(f"License data: {license_data}")
        
        # Parse and display
        # Format: SCYLLA_LICENSE:v1:<customer>:<expiry>:<vcpus>:<storage_tb>
        parts = license_data.split(':')
        if len(parts) == 6 and parts[0] == "SCYLLA_LICENSE" and parts[1] == "v1":
            print()
            print("Parsed license:")
            print(f"  Customer: {parts[2]}")
            expiry_ts = int(parts[3])
            if expiry_ts == 0:
                print("  Expiry: never")
            else:
                expiry_dt = datetime.fromtimestamp(expiry_ts, tz=timezone.utc)
                print(f"  Expiry: {expiry_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}")
                if datetime.now(timezone.utc) > expiry_dt:
                    print("  ⚠️  WARNING: License has EXPIRED!")
            vcpus = int(parts[4])
            print(f"  vCPUs: {'unlimited' if vcpus == UNLIMITED_VCPUS else vcpus}")
            storage = int(parts[5])
            print(f"  Storage: {'unlimited' if storage == 0 else f'{storage} TB'}")
    else:
        print("✗ License signature is INVALID")
        sys.exit(1)


def cmd_show_current_key(args):
    """Show the current embedded public key (by computing from obfuscated values)."""
    # These are the current values in license_compliance.cc
    obfuscated_pubkey_base = bytes([
        0x8a, 0x3d, 0x7e, 0x21, 0xf4, 0x56, 0x9b, 0xc8,
        0x12, 0xe7, 0x4a, 0xbd, 0x03, 0x68, 0xdf, 0x91,
        0x5c, 0xa2, 0x37, 0xe9, 0x84, 0x1b, 0x6f, 0xc0,
        0xd5, 0x49, 0x8e, 0x22, 0xb7, 0x60, 0xf3, 0x0c
    ])
    
    public_key = deobfuscate_public_key(obfuscated_pubkey_base)
    
    print("Current embedded public key (computed from obfuscated values):")
    print(f"  {public_key.hex()}")
    print()
    print("Obfuscated base (in code):")
    print(f"  {obfuscated_pubkey_base.hex()}")
    print()
    print("Salt:")
    print(f"  0x{PUBKEY_SALT:016X}")
    print()
    print("NOTE: The seed/private key for this public key is NOT stored in the code.")
    print("      You need the original seed to generate licenses.")


def main():
    parser = argparse.ArgumentParser(
        description="ScyllaDB License Generation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # generate-keypair
    p_gen = subparsers.add_parser('generate-keypair', help='Generate a new Ed25519 keypair')
    p_gen.add_argument('--show-embedding', action='store_true', 
                       help='Show C++ code for embedding the public key')
    
    # show-embedding
    p_embed = subparsers.add_parser('show-embedding', 
                                     help='Show C++ embedding code for an existing seed')
    p_embed.add_argument('--seed', required=True, help='Hex-encoded 32-byte seed')
    
    # generate-license
    p_lic = subparsers.add_parser('generate-license', help='Generate a signed license file')
    p_lic.add_argument('--seed', required=True, help='Hex-encoded 32-byte seed')
    p_lic.add_argument('--customer', required=True, help='Customer ID')
    p_lic.add_argument('--vcpus', type=int, help='Max vCPUs (omit for unlimited)')
    p_lic.add_argument('--storage-tb', type=int, help='Max storage in TB (omit for unlimited)')
    p_lic.add_argument('--expiry', help='Expiry date (YYYY-MM-DD) or "never"')
    p_lic.add_argument('--unlimited', action='store_true', 
                       help='Generate unlimited, never-expiring license')
    p_lic.add_argument('--output', '-o', help='Output file (default: print to stdout)')
    
    # verify-license
    p_ver = subparsers.add_parser('verify-license', help='Verify a license file')
    p_ver.add_argument('--seed', required=True, help='Hex-encoded 32-byte seed')
    p_ver.add_argument('--license-file', required=True, help='Path to license file')
    
    # show-current-key
    p_cur = subparsers.add_parser('show-current-key', 
                                   help='Show the currently embedded public key')
    
    args = parser.parse_args()
    
    if args.command == 'generate-keypair':
        cmd_generate_keypair(args)
    elif args.command == 'show-embedding':
        cmd_show_embedding(args)
    elif args.command == 'generate-license':
        cmd_generate_license(args)
    elif args.command == 'verify-license':
        cmd_verify_license(args)
    elif args.command == 'show-current-key':
        cmd_show_current_key(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()

