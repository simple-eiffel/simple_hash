# S04: FEATURE SPECS - simple_hash

**Document**: S04-FEATURE-SPECS.md
**Library**: simple_hash
**Status**: BACKWASH (reverse-engineered from implementation)
**Date**: 2026-01-23

---

## SHA-1 Features

| Feature | Signature | Description |
|---------|-----------|-------------|
| sha1 | (STRING): STRING | SHA-1 as hex |
| sha1_bytes | (STRING): ARRAY [NATURAL_8] | SHA-1 as bytes |

## SHA-256 Features

| Feature | Signature | Description |
|---------|-----------|-------------|
| sha256 | (STRING): STRING | SHA-256 as hex |
| sha256_bytes | (STRING): ARRAY [NATURAL_8] | SHA-256 as bytes |
| sha256_file | (STRING): detachable STRING | Hash file as hex |
| sha256_file_bytes | (STRING): detachable ARRAY[...] | Hash file as bytes |

## SHA-512 Features

| Feature | Signature | Description |
|---------|-----------|-------------|
| sha512 | (STRING): STRING | SHA-512 as hex |
| sha512_bytes | (STRING): ARRAY [NATURAL_8] | SHA-512 as bytes |
| sha512_file | (STRING): detachable STRING | Hash file as hex |
| sha512_file_bytes | (STRING): detachable ARRAY[...] | Hash file as bytes |

## HMAC Features

| Feature | Signature | Description |
|---------|-----------|-------------|
| hmac_sha256 | (STRING, STRING): STRING | HMAC-SHA256 as hex |
| hmac_sha256_bytes | (STRING, STRING): ARRAY[...] | HMAC-SHA256 as bytes |
| hmac_sha512 | (STRING, STRING): STRING | HMAC-SHA512 as hex |
| hmac_sha512_bytes | (STRING, STRING): ARRAY[...] | HMAC-SHA512 as bytes |

## MD5 Features

| Feature | Signature | Description |
|---------|-----------|-------------|
| md5 | (STRING): STRING | MD5 as hex |
| md5_bytes | (STRING): ARRAY [NATURAL_8] | MD5 as bytes |
| md5_file | (STRING): detachable STRING | Hash file as hex |
| md5_file_bytes | (STRING): detachable ARRAY[...] | Hash file as bytes |

## Secure Comparison Features

| Feature | Signature | Description |
|---------|-----------|-------------|
| secure_compare | (STRING, STRING): BOOLEAN | Constant-time string compare |
| secure_compare_bytes | (ARRAY, ARRAY): BOOLEAN | Constant-time byte compare |
| secure_compare_hex | (STRING, STRING): BOOLEAN | Compare hex strings |

## Utility Features

| Feature | Signature | Description |
|---------|-----------|-------------|
| bytes_to_hex | (ARRAY[NATURAL_8]): STRING | Convert bytes to hex |
| hex_to_bytes | (STRING): ARRAY[NATURAL_8] | Convert hex to bytes |

## Model Features (MML)

| Feature | Signature | Description |
|---------|-----------|-------------|
| bytes_model | (ARRAY): MML_SEQUENCE | Byte array model |
| string_bytes_model | (STRING): MML_SEQUENCE | String as byte model |
| hex_model | (STRING): MML_SET | Hex char set model |

## Constants

| Feature | Type | Value |
|---------|------|-------|
| Hex_chars | STRING | "0123456789abcdef" |
| File_buffer_size | INTEGER | 8192 |
| Sha1_output_bytes | INTEGER | 20 |
| Sha256_output_bytes | INTEGER | 32 |
| Sha512_output_bytes | INTEGER | 64 |
| Md5_output_bytes | INTEGER | 16 |
