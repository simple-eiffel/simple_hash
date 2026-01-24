# S07: SPEC SUMMARY - simple_hash

**Document**: S07-SPEC-SUMMARY.md
**Library**: simple_hash
**Status**: BACKWASH (reverse-engineered from implementation)
**Date**: 2026-01-23

---

## Executive Summary

simple_hash provides cryptographic hashing capabilities for Eiffel applications, including SHA-1/256/512, HMAC, MD5, and constant-time secure comparison, all implemented in pure Eiffel with no external dependencies.

## Key Capabilities

| Capability | Algorithms | Status |
|------------|------------|--------|
| Secure Hash | SHA-256, SHA-512 | Complete |
| Legacy Hash | SHA-1, MD5 | Complete |
| HMAC | SHA-256, SHA-512 | Complete |
| Secure Compare | Constant-time | Complete |
| File Hashing | All algorithms | Complete |

## API Highlights

```eiffel
-- Basic hashing
local
    hasher: SIMPLE_HASH
do
    create hasher.make

    -- SHA-256 (recommended)
    print (hasher.sha256 ("Hello, World!"))

    -- HMAC for API signatures
    print (hasher.hmac_sha256 (api_key, request_body))

    -- Secure comparison (constant-time)
    if hasher.secure_compare (expected, received) then
        -- Match
    end

    -- File hashing
    if attached hasher.sha256_file ("/path/to/file") as h then
        print (h)
    end
end
```

## Security Notes

- **Use SHA-256**: For general purpose hashing
- **Use HMAC**: For message authentication
- **Use secure_compare**: When comparing secrets
- **Avoid MD5/SHA-1**: For security (SHA-1 OK for WebSocket)

## Quality Attributes

- **Design by Contract**: Full preconditions/postconditions
- **MML Verification**: Model-based contracts
- **Void Safety**: All code void-safe
- **No Dependencies**: Pure Eiffel implementation
- **Constant-Time**: Secure comparison prevents timing attacks
