# 7S-05: SECURITY - simple_hash

**Document**: 7S-05-SECURITY.md
**Library**: simple_hash
**Status**: BACKWASH (reverse-engineered from implementation)
**Date**: 2026-01-23

---

## Security Considerations

### Algorithm Security

| Algorithm | Status | Use Case |
|-----------|--------|----------|
| SHA-256 | Secure | General purpose, recommended |
| SHA-512 | Secure | High security requirements |
| SHA-1 | Deprecated | WebSocket only (RFC requirement) |
| MD5 | Broken | Checksums only, not security |

### Attack Vectors

1. **Timing Attacks**
   - Risk: String comparison leaks timing info
   - Mitigation: `secure_compare` uses constant-time XOR
   - Status: MITIGATED

2. **Length Extension**
   - Risk: SHA-256 vulnerable to length extension
   - Mitigation: Use HMAC for authentication
   - Status: Use HMAC pattern

3. **Rainbow Tables**
   - Risk: Precomputed hash lookups
   - Mitigation: Use salted hashes (application responsibility)
   - Status: Application pattern

### Secure Comparison

The `secure_compare` and `secure_compare_bytes` features use constant-time comparison:

```eiffel
-- XOR all bytes, accumulate result
-- Always compares ALL bytes regardless of where difference is
-- Prevents timing attacks
```

### Recommendations

1. **Use SHA-256**: Default choice for most applications
2. **Use HMAC**: For message authentication
3. **Use secure_compare**: When comparing secrets
4. **Salt Passwords**: Don't hash passwords directly
5. **Don't Use MD5**: For anything security-related
6. **SHA-1 Only**: For WebSocket handshake (required by spec)

### Known Vulnerabilities

None in implementation. Algorithm-level concerns documented above.
