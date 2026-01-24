# S03: CONTRACTS - simple_hash

**Document**: S03-CONTRACTS.md
**Library**: simple_hash
**Status**: BACKWASH (reverse-engineered from implementation)
**Date**: 2026-01-23

---

## SIMPLE_HASH Contracts

### Class Invariant
```eiffel
invariant
    buffer_exists: working_buffer /= Void
    buffer_size: working_buffer.count = 64
```

### SHA-256 Contracts
```eiffel
sha256 (a_input: STRING): STRING
    ensure
        correct_length: Result.count = Sha256_output_bytes * 2
        lowercase_hex: across Result as c all c.item.is_lower or c.item.is_digit end
        deterministic: Result.same_string (sha256 (a_input))

sha256_bytes (a_input: STRING): ARRAY [NATURAL_8]
    ensure
        correct_length: Result.count = Sha256_output_bytes
        model_length: bytes_model (Result).count = Sha256_output_bytes
        deterministic: bytes_model (Result) |=| bytes_model (sha256_bytes (a_input))
```

### SHA-512 Contracts
```eiffel
sha512 (a_input: STRING): STRING
    ensure
        correct_length: Result.count = Sha512_output_bytes * 2
        lowercase_hex: across Result as c all c.item.is_lower or c.item.is_digit end
        deterministic: Result.same_string (sha512 (a_input))
```

### HMAC Contracts
```eiffel
hmac_sha256 (a_key, a_message: STRING): STRING
    ensure
        correct_length: Result.count = Sha256_output_bytes * 2
        lowercase_hex: across Result as c all c.item.is_lower or c.item.is_digit end
        deterministic: Result.same_string (hmac_sha256 (a_key, a_message))
```

### Secure Compare Contracts
```eiffel
secure_compare (a_left, a_right: STRING): BOOLEAN
    ensure
        same_strings_equal: a_left.same_string (a_right) implies Result
        different_strings_unequal: not a_left.same_string (a_right) implies not Result
        symmetric: Result = secure_compare (a_right, a_left)

secure_compare_bytes (a_left, a_right: ARRAY [NATURAL_8]): BOOLEAN
    ensure
        model_equal_implies_result: (bytes_model (a_left) |=| bytes_model (a_right)) implies Result
        symmetric: Result = secure_compare_bytes (a_right, a_left)
```

### Utility Contracts
```eiffel
bytes_to_hex (a_bytes: ARRAY [NATURAL_8]): STRING
    ensure
        correct_length: Result.count = a_bytes.count * 2
        lowercase_hex: across Result as c all c.item.is_lower or c.item.is_digit end
        roundtrip: bytes_model (hex_to_bytes (Result)) |=| bytes_model (a_bytes)

hex_to_bytes (a_hex: STRING): ARRAY [NATURAL_8]
    require
        even_length: a_hex.count \\ 2 = 0
        valid_hex: across a_hex as c all Hex_chars.has (c.item.as_lower) end
    ensure
        correct_length: Result.count = a_hex.count // 2
```

### File Hashing Contracts
```eiffel
sha256_file (a_path: STRING): detachable STRING
    require
        path_not_empty: not a_path.is_empty
    ensure
        correct_length: Result /= Void implies Result.count = Sha256_output_bytes * 2
        lowercase_hex: attached Result as r implies across r as c all c.item.is_lower or c.item.is_digit end
```
