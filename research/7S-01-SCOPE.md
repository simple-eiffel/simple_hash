# 7S-01: SCOPE - simple_hash

**Document**: 7S-01-SCOPE.md
**Library**: simple_hash
**Status**: BACKWASH (reverse-engineered from implementation)
**Date**: 2026-01-23

---

## Problem Domain

simple_hash provides cryptographic hashing capabilities for Eiffel applications:

1. **SHA Family** - SHA-1, SHA-256, SHA-512 hash functions
2. **HMAC** - Keyed-hash message authentication (HMAC-SHA256, HMAC-SHA512)
3. **MD5** - Legacy hash for checksums (not security)
4. **Secure Comparison** - Constant-time comparison to prevent timing attacks
5. **File Hashing** - Hash files on disk

## Target Users

- **Security Developers**: Password hashing, token generation
- **API Developers**: HMAC signatures for APIs
- **File Integrity**: Checksum verification
- **WebSocket Developers**: SHA-1 for WebSocket handshake (RFC 6455)

## Boundaries

### In Scope
- SHA-1, SHA-256, SHA-512 hash computation
- HMAC-SHA256, HMAC-SHA512 computation
- MD5 hash (for legacy/checksum use only)
- Hex encoding/decoding
- File hashing
- Constant-time comparison

### Out of Scope
- Encryption/decryption (not hashing)
- Key derivation (PBKDF2, bcrypt, etc.)
- Digital signatures
- Random number generation

## Dependencies

- EiffelStudio kernel libraries
- MML for model verification
- No external C libraries

## Integration Points

- SIMPLE_HASH facade class
- Byte array and hex string outputs
- File path inputs for file hashing
