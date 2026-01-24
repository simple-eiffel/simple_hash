# 7S-04: SIMPLE-STAR - simple_hash

**Document**: 7S-04-SIMPLE-STAR.md
**Library**: simple_hash
**Status**: BACKWASH (reverse-engineered from implementation)
**Date**: 2026-01-23

---

## Ecosystem Integration

### Dependencies (Incoming)

| Library | Usage |
|---------|-------|
| mml | Model verification in contracts |

### Dependents (Outgoing)

| Library | Usage |
|---------|-------|
| simple_websocket | SHA-1 for handshake |
| simple_http | HMAC for signatures |
| simple_auth | Password hashing |
| Various | File integrity |

### Integration Patterns

1. **Basic Hashing Pattern**
```eiffel
local
    hasher: SIMPLE_HASH
    digest: STRING
do
    create hasher.make
    digest := hasher.sha256 ("Hello, World!")
    -- digest is 64-char hex string
end
```

2. **HMAC Pattern**
```eiffel
local
    hasher: SIMPLE_HASH
    signature: STRING
do
    create hasher.make
    signature := hasher.hmac_sha256 (secret_key, message)
    -- Use for API authentication
end
```

3. **Secure Comparison Pattern**
```eiffel
local
    hasher: SIMPLE_HASH
do
    create hasher.make
    if hasher.secure_compare (expected_hash, received_hash) then
        -- Hashes match
    end
end
```

4. **File Hashing Pattern**
```eiffel
local
    hasher: SIMPLE_HASH
    file_hash: detachable STRING
do
    create hasher.make
    file_hash := hasher.sha256_file ("/path/to/file")
    if attached file_hash as h then
        -- h is file hash
    end
end
```

### API Compatibility

- Follows simple_* naming conventions
- Uses MML for model verification
- Returns both STRING and ARRAY [NATURAL_8]
