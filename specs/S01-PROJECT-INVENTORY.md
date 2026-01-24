# S01: PROJECT INVENTORY - simple_hash

**Document**: S01-PROJECT-INVENTORY.md
**Library**: simple_hash
**Status**: BACKWASH (reverse-engineered from implementation)
**Date**: 2026-01-23

---

## Project Structure

```
simple_hash/
├── src/
│   └── simple_hash.e       -- All hash implementations
├── testing/
│   ├── test_app.e          -- Test runner
│   └── lib_tests.e         -- Test cases
├── docs/
│   ├── index.html          -- Documentation
│   └── api/
│       └── simple_hash.html-- API reference
├── research/               -- 7S research documents
├── specs/                  -- Specification documents
└── simple_hash.ecf         -- ECF configuration
```

## Source Files

### Core Classes (src/)

| File | Lines | Purpose |
|------|-------|---------|
| simple_hash.e | 1,305 | Complete hash library |

### Test Files (testing/)

| File | Lines | Purpose |
|------|-------|---------|
| test_app.e | 30 | Test application entry |
| lib_tests.e | 100+ | Test cases |

## Configuration Files

| File | Purpose |
|------|---------|
| simple_hash.ecf | Main ECF configuration |

## External References (EIS)

```eiffel
EIS: "name=Documentation", "src=../docs/index.html"
EIS: "name=API Reference", "src=../docs/api/simple_hash.html"
EIS: "name=SHA-256 Spec", "src=https://csrc.nist.gov/publications/detail/fips/180/4/final"
```

## Dependencies

| Library | Purpose |
|---------|---------|
| mml | Model verification (MML_SEQUENCE, MML_SET) |
