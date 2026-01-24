# 7S-02: STANDARDS - simple_hash

**Document**: 7S-02-STANDARDS.md
**Library**: simple_hash
**Status**: BACKWASH (reverse-engineered from implementation)
**Date**: 2026-01-23

---

## Applicable Standards

### Hash Functions

1. **FIPS 180-4 (Secure Hash Standard)**
   - Reference: https://csrc.nist.gov/publications/detail/fips/180/4/final
   - SHA-1 (160 bits) - Deprecated for security
   - SHA-256 (256 bits) - Recommended
   - SHA-512 (512 bits) - High security

2. **RFC 1321 (MD5)**
   - Reference: https://tools.ietf.org/html/rfc1321
   - 128-bit hash
   - Cryptographically broken - checksums only

### HMAC

1. **RFC 2104 (HMAC)**
   - Reference: https://tools.ietf.org/html/rfc2104
   - Keyed-Hash Message Authentication Code
   - HMAC-SHA256, HMAC-SHA512

### WebSocket

1. **RFC 6455 (WebSocket Protocol)**
   - Reference: https://tools.ietf.org/html/rfc6455
   - Requires SHA-1 for handshake
   - Reason SHA-1 is included despite deprecation

## Implementation Compliance

| Standard | Compliance Level | Notes |
|----------|------------------|-------|
| FIPS 180-4 SHA-1 | Full | For WebSocket |
| FIPS 180-4 SHA-256 | Full | Recommended |
| FIPS 180-4 SHA-512 | Full | High security |
| RFC 1321 MD5 | Full | Checksums only |
| RFC 2104 HMAC | Full | SHA256, SHA512 |

## Test Vectors

Implementation verified against NIST test vectors:
- SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
- SHA-512("abc") = ddaf35a193617aba...
- MD5("abc") = 900150983cd24fb0d6963f7d28e17f72
