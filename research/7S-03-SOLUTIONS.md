# 7S-03: SOLUTIONS - simple_hash

**Document**: 7S-03-SOLUTIONS.md
**Library**: simple_hash
**Status**: BACKWASH (reverse-engineered from implementation)
**Date**: 2026-01-23

---

## Existing Solutions Comparison

### Hash Libraries

| Solution | Language | Pros | Cons |
|----------|----------|------|------|
| OpenSSL | C | Complete, fast | External dependency |
| crypto-js | JavaScript | Easy, web-ready | Wrong language |
| hashlib | Python | Standard library | Wrong language |
| EiffelCrypto | Eiffel | Native | Abandoned |
| simple_hash | Eiffel | Native, DBC, no deps | Pure Eiffel (slower) |

### Why Pure Eiffel?

- No external dependencies (portable)
- Full Design by Contract
- Void safety guaranteed
- No C library linking issues
- Complete control over implementation

## Design Decisions

1. **Single Class**: SIMPLE_HASH facade for all operations
2. **Dual Output**: Both byte arrays and hex strings
3. **Constant-Time**: Secure comparison to prevent timing attacks
4. **File Support**: Direct file hashing without loading all at once
5. **MML Models**: Model-based contracts for verification

## Trade-offs

- **Performance**: Pure Eiffel slower than C libraries
- **Features**: No encryption, just hashing
- **Key Derivation**: No PBKDF2/bcrypt (use simple_key_derivation)

## Recommendation

Use simple_hash for:
- Password hashing verification (store SHA-256 of passwords)
- HMAC signatures for APIs
- File integrity verification
- WebSocket handshake (SHA-1 required by spec)

Do NOT use simple_hash for:
- High-performance bulk hashing (use C library)
- Encryption (use simple_crypto)
