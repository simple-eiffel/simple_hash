<p align="center">
  <img src="https://raw.githubusercontent.com/simple-eiffel/.github/main/profile/assets/logo.png" alt="simple_ library logo" width="400">
</p>

# simple_hash

**[Documentation](https://simple-eiffel.github.io/simple_hash/)** | **[Watch the Build Video](https://youtu.be/Rh3KhoK_W5U)**

Lightweight cryptographic hashing library for Eiffel.

## Features

- **SHA-256** - Secure hash (FIPS 180-4)
- **HMAC-SHA256** - Keyed-hash message authentication (RFC 2104)
- **MD5** - Legacy checksums (not for security)
- **Design by Contract** - Full preconditions/postconditions
- **Pure Eiffel** - No external dependencies

## Installation

Add to your ECF:

```xml
<library name="simple_hash" location="$SIMPLE_EIFFEL/simple_hash/simple_hash.ecf"/>
```

Set environment variable (one-time setup for all simple_* libraries):
```
SIMPLE_EIFFEL=D:\prod
```

## Usage

### SHA-256 Hashing

```eiffel
local
    hasher: SIMPLE_HASH
    digest: STRING
do
    create hasher.make

    digest := hasher.sha256 ("Hello, World!")
    -- Result: "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
end
```

### HMAC-SHA256 (for JWT, API signatures)

```eiffel
local
    hasher: SIMPLE_HASH
    signature: STRING
do
    create hasher.make

    signature := hasher.hmac_sha256 ("secret-key", "message")
    -- 64-character hex string
end
```

### MD5 (Legacy only)

```eiffel
local
    hasher: SIMPLE_HASH
    checksum: STRING
do
    create hasher.make

    -- WARNING: MD5 is cryptographically broken
    checksum := hasher.md5 ("data")
end
```

## API Reference

### Hashing

| Feature | Description |
|---------|-------------|
| `sha256 (STRING): STRING` | SHA-256 hash as 64 hex chars |
| `sha256_bytes (STRING): ARRAY[NATURAL_8]` | SHA-256 hash as 32 bytes |
| `hmac_sha256 (key, msg): STRING` | HMAC-SHA256 as 64 hex chars |
| `hmac_sha256_bytes (key, msg): ARRAY[NATURAL_8]` | HMAC-SHA256 as 32 bytes |
| `md5 (STRING): STRING` | MD5 hash as 32 hex chars |
| `md5_bytes (STRING): ARRAY[NATURAL_8]` | MD5 hash as 16 bytes |

### Utilities

| Feature | Description |
|---------|-------------|
| `bytes_to_hex (bytes): STRING` | Convert bytes to hex string |
| `hex_to_bytes (hex): ARRAY[NATURAL_8]` | Convert hex string to bytes |

## Use Cases

- **JWT tokens** - HMAC-SHA256 for HS256 signatures
- **API authentication** - Request signing
- **Data integrity** - File checksums
- **Password hashing** - SHA-256 with salt

## Dependencies

- EiffelBase only

## License

MIT License - Copyright (c) 2024-2025, Larry Rix
