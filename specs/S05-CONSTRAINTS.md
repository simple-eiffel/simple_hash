# S05: CONSTRAINTS - simple_hash

**Document**: S05-CONSTRAINTS.md
**Library**: simple_hash
**Status**: BACKWASH (reverse-engineered from implementation)
**Date**: 2026-01-23

---

## Technical Constraints

### Input Constraints

1. **String Input**
   - Any STRING (including empty)
   - Treated as bytes (character codes)
   - No encoding assumptions

2. **Hex Input**
   - Must have even length
   - Characters: 0-9, a-f, A-F
   - Case-insensitive

3. **File Input**
   - Path must not be empty
   - File must exist and be readable
   - Returns Void if file cannot be read

### Output Constraints

1. **Hex Output**
   - Always lowercase
   - Fixed length per algorithm
   - SHA-1: 40 characters
   - SHA-256: 64 characters
   - SHA-512: 128 characters
   - MD5: 32 characters

2. **Byte Output**
   - Array indexed from 1
   - Fixed length per algorithm
   - SHA-1: 20 bytes
   - SHA-256: 32 bytes
   - SHA-512: 64 bytes
   - MD5: 16 bytes

### Algorithm Constraints

1. **Message Size**
   - SHA-256: Up to 2^64 bits (practical: memory limited)
   - SHA-512: Up to 2^128 bits
   - Entire message must fit in memory

2. **Key Size (HMAC)**
   - Any key length supported
   - Keys > block size are hashed first
   - Block size: 64 bytes (SHA-256), 128 bytes (SHA-512)

### Performance Constraints

- Pure Eiffel implementation
- Single-threaded
- Entire file loaded for file hashing
- Not optimized for bulk operations

## Platform Constraints

| Platform | Support |
|----------|---------|
| Windows | Full |
| Linux | Full |
| macOS | Full |

No platform-specific code required.
