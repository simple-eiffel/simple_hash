# S02: CLASS CATALOG - simple_hash

**Document**: S02-CLASS-CATALOG.md
**Library**: simple_hash
**Status**: BACKWASH (reverse-engineered from implementation)
**Date**: 2026-01-23

---

## Core Classes

| Class | Type | Description |
|-------|------|-------------|
| SIMPLE_HASH | Effective | Complete cryptographic hash library |

## SIMPLE_HASH Details

**Purpose**: Single-class library providing all hash operations

### Feature Categories

1. **SHA-1** (for WebSocket, deprecated for security)
   - sha1, sha1_bytes

2. **SHA-256** (recommended)
   - sha256, sha256_bytes
   - sha256_file, sha256_file_bytes

3. **SHA-512** (high security)
   - sha512, sha512_bytes
   - sha512_file, sha512_file_bytes

4. **HMAC**
   - hmac_sha256, hmac_sha256_bytes
   - hmac_sha512, hmac_sha512_bytes

5. **MD5** (checksums only)
   - md5, md5_bytes
   - md5_file, md5_file_bytes

6. **Secure Comparison**
   - secure_compare (strings)
   - secure_compare_bytes (byte arrays)
   - secure_compare_hex (hex strings)

7. **Utilities**
   - bytes_to_hex, hex_to_bytes

8. **MML Models**
   - bytes_model, string_bytes_model, hex_model

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| Sha1_output_bytes | 20 | SHA-1 output size |
| Sha256_output_bytes | 32 | SHA-256 output size |
| Sha512_output_bytes | 64 | SHA-512 output size |
| Md5_output_bytes | 16 | MD5 output size |
| File_buffer_size | 8192 | File read buffer |
| Hex_chars | "0123456789abcdef" | Hex alphabet |

## No Inheritance

SIMPLE_HASH is a standalone class inheriting only from ANY.
