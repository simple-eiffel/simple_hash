# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-10-08

### Fixed
- **D15: file hashing was slow and loaded the whole file.** `sha256_file`, `sha512_file` and
  `md5_file` read the entire file into a STRING, copied it into an ARRAYED_LIST, an ARRAY and a
  padded ARRAY, then compressed it in Eiffel: 12-15 MB/s finalized, 0.88 MB/s with contracts, and a
  peak working set of about 5x the file (1 GB file: 5,282 MB). Files are now streamed in
  `File_chunk_size` (256 KB) pieces through one reusable C-heap buffer: 356 MB/s SHA-256 on a
  1 GiB file with a flat 7 MB working set (365 MB/s, 12 MB with contracts).
- **File hashing took only 8-bit paths.** Every file feature now takes `READABLE_STRING_GENERAL`
  (STRING callers are unaffected), and new `*_path (PATH)` features exist, so Hebrew, Greek and
  other Unicode file names work. Note: a STRING_8 name is still taken as Latin-1 characters, not
  decoded as UTF-8; pass a STRING_32 for Unicode names.
- **Files over 2 GB.** Reads use Win32 `CreateFileW`/`ReadFile` rather than ISE `FILE`, whose
  32-bit `count` breaks `read_to_managed_pointer` preconditions at 2 GB in contract builds.
- A directory now answers `Void` like any other unreadable path.

### Added
- `SIMPLE_HASH_STATE` (deferred) with `SIMPLE_SHA256_STATE`, `SIMPLE_SHA512_STATE`,
  `SIMPLE_SHA1_STATE`, `SIMPLE_MD5_STATE`: incremental hashing (`update`, `update_bytes`,
  `update_from_managed`, `finish`, `digest`, `digest_hex`, `reset`, `byte_count`) in constant memory.
- `sha1_file`, `sha1_file_bytes`, `sha256_path`, `sha512_path`, `sha1_path`, `md5_path`,
  `File_chunk_size`.
- 22 tests (`STREAMING_TESTS`): FIPS 180-4 vectors ("", "abc", 448-bit, 896-bit, one million 'a')
  for SHA-1, SHA-256, SHA-512 and MD5; the RFC 1321 suite; padding-boundary lengths 55-129;
  ragged incremental feeding through every update route; a 798,777-byte multi-chunk file
  (file digest = in-memory digest = expected); a Hebrew+Greek file name via STRING_32 and PATH;
  empty file; directory; missing file; RFC 4231 cases 6 and 7. Expected digests come from Python
  hashlib, cross-checked with coreutils `sha*sum`/`md5sum`.

### Changed
- Every digest (in-memory and file) runs through the streaming states. Block compression is
  one-class inline C over C-heap memory only, declared `C blocking`, so a long hash never holds up
  a garbage collection on another SCOOP processor. A best-effort pure-Eiffel SHA-256 compression
  was measured first at 93 MB/s finalized (22 MB/s with contracts), below the 200 MB/s target.
- HMAC-SHA256/512 stream the message instead of concatenating it with the padded key.
- In-memory hashing: 100 MB SHA-256 6,658 ms -> 267 ms; peak working set +200 MB -> +0 MB.
- All digests are byte-identical to 1.0.0 (verified on the FIPS/RFC vectors and on 10, 100, 350
  and 1,024 MB random files against 1.0.0 output and coreutils).
- Removed only `{NONE}` helpers (`sha256_pad`, `sha512_pad`, `md5_pad`, round-constant tables,
  rotations, `bytes_to_string`, `put_nat*`). `File_buffer_size` is kept, unused.
- simple_hash now builds on Windows only: SIMPLE_HASH holds the Win32 file-read externals (the compression C is portable).

### Earlier changes since 1.0.0
- Testing config updates, AutoTest fixes, .gitignore cleanup
- Migrate to simple_testing library
- Remove redundant result_not_void postconditions
- Add SHA-1 hash support for WebSocket handshake
- Add missing loop variants for Design by Contract compliance
- Add YouTube build video link to README
- Initial commit: simple_hash library

## [1.0.0] - 2025-12-08

### Added
- Initial release
- Core functionality implemented
- Test suite with comprehensive coverage
- Documentation and examples

[Unreleased]: https://github.com/simple-eiffel/simple_hash/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/simple-eiffel/simple_hash/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/simple-eiffel/simple_hash/releases/tag/v1.0.0
