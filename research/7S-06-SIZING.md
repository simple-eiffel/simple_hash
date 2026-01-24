# 7S-06: SIZING - simple_hash

**Document**: 7S-06-SIZING.md
**Library**: simple_hash
**Status**: BACKWASH (reverse-engineered from implementation)
**Date**: 2026-01-23

---

## Implementation Size

### Source Metrics

| File | Lines | Purpose |
|------|-------|---------|
| simple_hash.e | 1,305 | All hash implementations |
| **Total** | 1,305 | Single-class library |

### Feature Breakdown

| Feature Set | Lines (approx) |
|-------------|----------------|
| SHA-1 | 150 |
| SHA-256 | 280 |
| SHA-512 | 300 |
| HMAC-SHA256 | 80 |
| HMAC-SHA512 | 80 |
| MD5 | 200 |
| File Hashing | 100 |
| Secure Compare | 100 |
| Utilities | 100 |
| Constants/Tables | 115 |

### Complexity Assessment

| Component | Complexity | Rationale |
|-----------|------------|-----------|
| SHA algorithms | Medium | Bit manipulation, padding |
| HMAC | Low | Wraps SHA |
| MD5 | Medium | Different padding |
| Secure compare | Low | Simple XOR loop |
| File hashing | Low | Read + hash |

### Development Effort

- **SHA-256**: 8 hours
- **SHA-512**: 6 hours (similar to 256)
- **SHA-1**: 4 hours
- **MD5**: 4 hours
- **HMAC**: 4 hours
- **Utilities**: 4 hours
- **Testing**: 8 hours
- **Total**: ~38 hours

### Binary Impact

| Target | Size Impact |
|--------|-------------|
| Executable | +50-100 KB |
| No dependencies | Standalone |

### Performance

- Pure Eiffel implementation
- Suitable for typical use cases
- Not optimized for bulk processing
