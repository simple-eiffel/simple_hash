# S06: BOUNDARIES - simple_hash

**Document**: S06-BOUNDARIES.md
**Library**: simple_hash
**Status**: BACKWASH (reverse-engineered from implementation)
**Date**: 2026-01-23

---

## System Boundaries

```
+---------------------------------------------+
|              Application Layer              |
|    (Auth, API signatures, file integrity)   |
+---------------------------------------------+
                     |
                     v
+---------------------------------------------+
|              SIMPLE_HASH                    |
|  +---------------+  +-------------------+   |
|  | SHA Family    |  | HMAC              |   |
|  | - SHA-1       |  | - HMAC-SHA256     |   |
|  | - SHA-256     |  | - HMAC-SHA512     |   |
|  | - SHA-512     |  |                   |   |
|  +---------------+  +-------------------+   |
|  +---------------+  +-------------------+   |
|  | MD5           |  | Secure Compare    |   |
|  | (legacy)      |  | (constant-time)   |   |
|  +---------------+  +-------------------+   |
+---------------------------------------------+
                     |
                     v
+---------------------------------------------+
|           EiffelStudio Runtime              |
|    (STRING, ARRAY, NATURAL types)           |
+---------------------------------------------+
```

## Interface Boundaries

### Public API (Exported to ANY)

All features of SIMPLE_HASH are public:
- All hash functions (sha*, md5*)
- All HMAC functions
- All secure compare functions
- All utility functions

### Internal Implementation (NONE export)

- Padding functions (sha256_pad, sha512_pad, md5_pad)
- Round constants (sha256_k, sha512_k, md5_k, md5_s)
- Bit operations (rotr32, rotl32, rotr64)
- Byte conversion helpers
- Working buffer

## Data Boundaries

### Input
- STRING: Text to hash
- STRING: HMAC key and message
- STRING: File path for file hashing
- ARRAY [NATURAL_8]: Byte data

### Output
- STRING: Hex-encoded hash
- ARRAY [NATURAL_8]: Raw hash bytes
- BOOLEAN: Comparison result
- MML types: Model verification

## Trust Boundaries

- Input is trusted (application responsibility)
- Hashing is deterministic
- No external dependencies
- Pure computation, no side effects
