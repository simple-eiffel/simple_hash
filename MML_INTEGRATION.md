# MML Integration - simple_hash

## Overview
Applied X03 Contract Assault with simple_mml on 2025-01-21.

## MML Classes Used
- `MML_SEQUENCE [NATURAL_8]` - Models hash output as byte sequence
- `MML_SET [CHARACTER]` - Models valid hex characters

## Model Queries Added
- `bytes_model: MML_SEQUENCE [NATURAL_8]` - Byte array as sequence
- `string_bytes_model: MML_SEQUENCE [NATURAL_8]` - String input as bytes
- `hex_model: MML_SET [CHARACTER]` - Hex chars as set

## Model-Based Postconditions
| Feature | Postcondition | Purpose |
|---------|---------------|---------|
| `sha1/256/512/md5` | `deterministic` | Same input = same output |
| `sha*_bytes` | `model_length`, `deterministic` | Correct output size |
| `hmac_sha*` | `deterministic`, `lowercase_hex` | HMAC correctness |
| `secure_compare` | `symmetric` | Comparison symmetry |
| `bytes_to_hex` | `roundtrip` | Reversible conversion |
| `hex_to_bytes` | `model_length` | Correct output size |

## Invariants Added
- `buffer_size: working_buffer.count = 64` - Buffer size constraint

## Bugs Found
None (23 redundant preconditions removed)

## Test Results
- Compilation: SUCCESS
- Tests: 44/44 PASS
