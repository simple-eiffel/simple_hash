note
	description: "[
		Simple Hash - Lightweight cryptographic hashing for Eiffel.

		Supports:
		- SHA-256, SHA-512 - Secure hashes, 256/512-bit output
		- HMAC-SHA256, HMAC-SHA512 - Keyed-hash message authentication
		- SHA-1 - Legacy, for protocols that require it (WebSocket handshake)
		- MD5 - Legacy hash (not for security, for checksums only)
		- File hashing - streamed in fixed chunks (flat memory, any size,
		  Unicode file names via STRING_32 or PATH)
		- Constant-time comparison - Prevents timing attacks

		Every digest runs through a streaming state (SIMPLE_SHA256_STATE,
		SIMPLE_SHA512_STATE, SIMPLE_SHA1_STATE, SIMPLE_MD5_STATE), usable
		directly for incremental hashing; block compression is inline C.

		Usage:
			create hasher.make
			digest := hasher.sha256 ("Hello, World!")
			hmac := hasher.hmac_sha256 ("secret", "message")

		Security:
			When comparing secrets (HMAC signatures, tokens, etc.), always use
			`secure_compare` or `secure_compare_bytes` to prevent timing attacks.
			Regular string comparison leaks information about which byte differs.
	]"
	author: "Larry Rix"
	date: "$Date$"
	revision: "$Revision$"
	EIS: "name=Documentation", "src=../docs/index.html", "protocol=URI", "tag=documentation"
	EIS: "name=API Reference", "src=../docs/api/simple_hash.html", "protocol=URI", "tag=api"
	EIS: "name=SHA-256 Spec", "src=https://csrc.nist.gov/publications/detail/fips/180/4/final", "protocol=URI", "tag=specification"

class
	SIMPLE_HASH

inherit
	ANY
		redefine
			default_create
		end

create
	make,
	default_create

feature {NONE} -- Initialization

	default_create
			-- Initialize the hasher.
		do
			make
		end

	make
			-- Initialize the hasher.
		do
			create working_buffer.make_filled (0, 1, 64)
		ensure
			buffer_ready: working_buffer.count = 64
		end


feature -- SHA-1

	sha1 (a_input: STRING): STRING
			-- Compute SHA-1 hash of `a_input' and return as hex string.
			-- Note: SHA-1 is deprecated for security; use SHA-256 for new applications.
			-- Required for WebSocket handshake per RFC 6455.
		local
			l_bytes: ARRAY [NATURAL_8]
		do
			l_bytes := sha1_bytes (a_input)
			Result := bytes_to_hex (l_bytes)
		ensure
			correct_length: Result.count = Sha1_output_bytes * 2
			lowercase_hex: across Result as c all c.item.is_lower or c.item.is_digit end
			deterministic: Result.same_string (sha1 (a_input))
		end

	sha1_bytes (a_input: STRING): ARRAY [NATURAL_8]
			-- Compute SHA-1 hash of `a_input' and return as 20 bytes.
		do
			Result := string_digest (create {SIMPLE_SHA1_STATE}.make, a_input)
		ensure
			correct_length: Result.count = Sha1_output_bytes
			model_length: bytes_model (Result).count = Sha1_output_bytes
			deterministic: bytes_model (Result) |=| bytes_model (sha1_bytes (a_input))
		end

feature -- SHA-256

	sha256 (a_input: STRING): STRING
			-- Compute SHA-256 hash of `a_input' and return as hex string.
		local
			l_bytes: ARRAY [NATURAL_8]
		do
			l_bytes := sha256_bytes (a_input)
			Result := bytes_to_hex (l_bytes)
		ensure
			correct_length: Result.count = Sha256_output_bytes * 2
			lowercase_hex: across Result as c all c.item.is_lower or c.item.is_digit end
			deterministic: Result.same_string (sha256 (a_input))
		end

	sha256_bytes (a_input: STRING): ARRAY [NATURAL_8]
			-- Compute SHA-256 hash of `a_input' and return as 32 bytes.
		do
			Result := string_digest (create {SIMPLE_SHA256_STATE}.make, a_input)
		ensure
			correct_length: Result.count = Sha256_output_bytes
			model_length: bytes_model (Result).count = Sha256_output_bytes
			deterministic: bytes_model (Result) |=| bytes_model (sha256_bytes (a_input))
		end

feature -- SHA-512

	sha512 (a_input: STRING): STRING
			-- Compute SHA-512 hash of `a_input' and return as hex string.
		local
			l_bytes: ARRAY [NATURAL_8]
		do
			l_bytes := sha512_bytes (a_input)
			Result := bytes_to_hex (l_bytes)
		ensure
			correct_length: Result.count = Sha512_output_bytes * 2
			lowercase_hex: across Result as c all c.item.is_lower or c.item.is_digit end
			deterministic: Result.same_string (sha512 (a_input))
		end

	sha512_bytes (a_input: STRING): ARRAY [NATURAL_8]
			-- Compute SHA-512 hash of `a_input' and return as 64 bytes.
		do
			Result := string_digest (create {SIMPLE_SHA512_STATE}.make, a_input)
		ensure
			correct_length: Result.count = Sha512_output_bytes
			model_length: bytes_model (Result).count = Sha512_output_bytes
			deterministic: bytes_model (Result) |=| bytes_model (sha512_bytes (a_input))
		end

feature -- HMAC-SHA256

	hmac_sha256 (a_key, a_message: STRING): STRING
			-- Compute HMAC-SHA256 of `a_message' using `a_key', return as hex string.
		local
			l_bytes: ARRAY [NATURAL_8]
		do
			l_bytes := hmac_sha256_bytes (a_key, a_message)
			Result := bytes_to_hex (l_bytes)
		ensure
			correct_length: Result.count = Sha256_output_bytes * 2
			lowercase_hex: across Result as c all c.item.is_lower or c.item.is_digit end
			deterministic: Result.same_string (hmac_sha256 (a_key, a_message))
		end

	hmac_sha256_bytes (a_key, a_message: STRING): ARRAY [NATURAL_8]
			-- Compute HMAC-SHA256 of `a_message' using `a_key', return as 32 bytes.
			-- HMAC(K, m) = H((K' xor opad) || H((K' xor ipad) || m))
		local
			l_key_bytes: ARRAY [NATURAL_8]
			l_inner_pad, l_outer_pad: ARRAY [NATURAL_8]
			l_state: SIMPLE_SHA256_STATE
			i: INTEGER
		do
				-- Get key bytes; if longer than the block size (64 bytes), hash it
			l_key_bytes := string_to_bytes (a_key)
			if l_key_bytes.count > 64 then
				l_key_bytes := sha256_bytes (a_key)
			end

				-- Inner and outer padded keys (the key zero-padded to 64 bytes)
			create l_inner_pad.make_filled (0x36, 1, 64)
			create l_outer_pad.make_filled (0x5c, 1, 64)
			from i := 1 until i > l_key_bytes.count loop
				l_inner_pad [i] := l_key_bytes [i].bit_xor (0x36) -- ipad
				l_outer_pad [i] := l_key_bytes [i].bit_xor (0x5c) -- opad
				i := i + 1
			variant
				l_key_bytes.count + 1 - i
			end

				-- Inner hash: H((K' xor ipad) || m), streamed - `a_message' is never copied
			create l_state.make
			l_state.update_bytes (l_inner_pad)
			l_state.update (a_message)
			l_state.finish

				-- Outer hash: H((K' xor opad) || inner_hash)
			l_inner_pad := l_state.digest
			l_state.reset
			l_state.update_bytes (l_outer_pad)
			l_state.update_bytes (l_inner_pad)
			l_state.finish
			Result := l_state.digest
		ensure
			correct_length: Result.count = Sha256_output_bytes
			model_length: bytes_model (Result).count = Sha256_output_bytes
			deterministic: bytes_model (Result) |=| bytes_model (hmac_sha256_bytes (a_key, a_message))
		end

feature -- HMAC-SHA512

	hmac_sha512 (a_key, a_message: STRING): STRING
			-- Compute HMAC-SHA512 of `a_message' using `a_key', return as hex string.
		local
			l_bytes: ARRAY [NATURAL_8]
		do
			l_bytes := hmac_sha512_bytes (a_key, a_message)
			Result := bytes_to_hex (l_bytes)
		ensure
			correct_length: Result.count = Sha512_output_bytes * 2
			lowercase_hex: across Result as c all c.item.is_lower or c.item.is_digit end
			deterministic: Result.same_string (hmac_sha512 (a_key, a_message))
		end

	hmac_sha512_bytes (a_key, a_message: STRING): ARRAY [NATURAL_8]
			-- Compute HMAC-SHA512 of `a_message' using `a_key', return as 64 bytes.
			-- HMAC(K, m) = H((K' xor opad) || H((K' xor ipad) || m))
			-- Block size for SHA-512 is 128 bytes.
		local
			l_key_bytes: ARRAY [NATURAL_8]
			l_inner_pad, l_outer_pad: ARRAY [NATURAL_8]
			l_state: SIMPLE_SHA512_STATE
			i: INTEGER
		do
				-- Get key bytes; if longer than the block size (128 bytes), hash it
			l_key_bytes := string_to_bytes (a_key)
			if l_key_bytes.count > 128 then
				l_key_bytes := sha512_bytes (a_key)
			end

				-- Inner and outer padded keys (the key zero-padded to 128 bytes)
			create l_inner_pad.make_filled (0x36, 1, 128)
			create l_outer_pad.make_filled (0x5c, 1, 128)
			from i := 1 until i > l_key_bytes.count loop
				l_inner_pad [i] := l_key_bytes [i].bit_xor (0x36) -- ipad
				l_outer_pad [i] := l_key_bytes [i].bit_xor (0x5c) -- opad
				i := i + 1
			variant
				l_key_bytes.count + 1 - i
			end

				-- Inner hash: H((K' xor ipad) || m), streamed - `a_message' is never copied
			create l_state.make
			l_state.update_bytes (l_inner_pad)
			l_state.update (a_message)
			l_state.finish

				-- Outer hash: H((K' xor opad) || inner_hash)
			l_inner_pad := l_state.digest
			l_state.reset
			l_state.update_bytes (l_outer_pad)
			l_state.update_bytes (l_inner_pad)
			l_state.finish
			Result := l_state.digest
		ensure
			correct_length: Result.count = Sha512_output_bytes
			model_length: bytes_model (Result).count = Sha512_output_bytes
			deterministic: bytes_model (Result) |=| bytes_model (hmac_sha512_bytes (a_key, a_message))
		end

feature -- MD5 (Legacy - not for security)

	md5 (a_input: STRING): STRING
			-- Compute MD5 hash of `a_input' and return as hex string.
			-- WARNING: MD5 is cryptographically broken. Use for checksums only.
		local
			l_bytes: ARRAY [NATURAL_8]
		do
			l_bytes := md5_bytes (a_input)
			Result := bytes_to_hex (l_bytes)
		ensure
			correct_length: Result.count = Md5_output_bytes * 2
			lowercase_hex: across Result as c all c.item.is_lower or c.item.is_digit end
			deterministic: Result.same_string (md5 (a_input))
		end

	md5_bytes (a_input: STRING): ARRAY [NATURAL_8]
			-- Compute MD5 hash of `a_input' and return as 16 bytes.
		do
			Result := string_digest (create {SIMPLE_MD5_STATE}.make, a_input)
		ensure
			correct_length: Result.count = Md5_output_bytes
			model_length: bytes_model (Result).count = Md5_output_bytes
			deterministic: bytes_model (Result) |=| bytes_model (md5_bytes (a_input))
		end

feature -- File Hashing

		-- Files are streamed in `File_chunk_size' pieces, so memory stays flat
		-- whatever the file size (no 2 GB limit). `a_path' may be any string:
		-- pass a STRING_32 (or a PATH) for Hebrew, Greek or other Unicode names.
		-- A STRING_8 is taken character for character (Latin-1), as RAW_FILE
		-- takes it, so it is NOT decoded as UTF-8.
		-- Each returns Void if the file does not exist, is a directory, cannot
		-- be opened for reading, or a read fails part way.

	sha256_file (a_path: READABLE_STRING_GENERAL): detachable STRING
			-- Compute SHA-256 hash of file at `a_path' and return as hex string.
			-- Returns Void if file cannot be read.
		require
			path_not_empty: not a_path.is_empty
		do
			Result := hex_or_void (sha256_file_bytes (a_path))
		ensure
			correct_length: Result /= Void implies Result.count = Sha256_output_bytes * 2
			lowercase_hex: attached Result as r implies across r as c all c.item.is_lower or c.item.is_digit end
		end

	sha256_file_bytes (a_path: READABLE_STRING_GENERAL): detachable ARRAY [NATURAL_8]
			-- Compute SHA-256 hash of file at `a_path' and return as 32 bytes.
			-- Returns Void if file cannot be read.
		require
			path_not_empty: not a_path.is_empty
		do
			Result := file_digest (create {SIMPLE_SHA256_STATE}.make, create {NATIVE_STRING}.make (a_path))
		ensure
			correct_length: Result /= Void implies Result.count = Sha256_output_bytes
			model_length: attached Result as r implies bytes_model (r).count = Sha256_output_bytes
		end

	sha512_file (a_path: READABLE_STRING_GENERAL): detachable STRING
			-- Compute SHA-512 hash of file at `a_path' and return as hex string.
			-- Returns Void if file cannot be read.
		require
			path_not_empty: not a_path.is_empty
		do
			Result := hex_or_void (sha512_file_bytes (a_path))
		ensure
			correct_length: Result /= Void implies Result.count = Sha512_output_bytes * 2
			lowercase_hex: attached Result as r implies across r as c all c.item.is_lower or c.item.is_digit end
		end

	sha512_file_bytes (a_path: READABLE_STRING_GENERAL): detachable ARRAY [NATURAL_8]
			-- Compute SHA-512 hash of file at `a_path' and return as 64 bytes.
			-- Returns Void if file cannot be read.
		require
			path_not_empty: not a_path.is_empty
		do
			Result := file_digest (create {SIMPLE_SHA512_STATE}.make, create {NATIVE_STRING}.make (a_path))
		ensure
			correct_length: Result /= Void implies Result.count = Sha512_output_bytes
			model_length: attached Result as r implies bytes_model (r).count = Sha512_output_bytes
		end

	sha1_file (a_path: READABLE_STRING_GENERAL): detachable STRING
			-- Compute SHA-1 hash of file at `a_path' and return as hex string.
			-- Returns Void if file cannot be read.
			-- Note: SHA-1 is deprecated for security; use SHA-256 for new applications.
		require
			path_not_empty: not a_path.is_empty
		do
			Result := hex_or_void (sha1_file_bytes (a_path))
		ensure
			correct_length: Result /= Void implies Result.count = Sha1_output_bytes * 2
			lowercase_hex: attached Result as r implies across r as c all c.item.is_lower or c.item.is_digit end
		end

	sha1_file_bytes (a_path: READABLE_STRING_GENERAL): detachable ARRAY [NATURAL_8]
			-- Compute SHA-1 hash of file at `a_path' and return as 20 bytes.
			-- Returns Void if file cannot be read.
		require
			path_not_empty: not a_path.is_empty
		do
			Result := file_digest (create {SIMPLE_SHA1_STATE}.make, create {NATIVE_STRING}.make (a_path))
		ensure
			correct_length: Result /= Void implies Result.count = Sha1_output_bytes
			model_length: attached Result as r implies bytes_model (r).count = Sha1_output_bytes
		end

	md5_file (a_path: READABLE_STRING_GENERAL): detachable STRING
			-- Compute MD5 hash of file at `a_path' and return as hex string.
			-- Returns Void if file cannot be read.
			-- WARNING: MD5 is cryptographically broken. Use for checksums only.
		require
			path_not_empty: not a_path.is_empty
		do
			Result := hex_or_void (md5_file_bytes (a_path))
		ensure
			correct_length: Result /= Void implies Result.count = Md5_output_bytes * 2
			lowercase_hex: attached Result as r implies across r as c all c.item.is_lower or c.item.is_digit end
		end

	md5_file_bytes (a_path: READABLE_STRING_GENERAL): detachable ARRAY [NATURAL_8]
			-- Compute MD5 hash of file at `a_path' and return as 16 bytes.
			-- Returns Void if file cannot be read.
		require
			path_not_empty: not a_path.is_empty
		do
			Result := file_digest (create {SIMPLE_MD5_STATE}.make, create {NATIVE_STRING}.make (a_path))
		ensure
			correct_length: Result /= Void implies Result.count = Md5_output_bytes
			model_length: attached Result as r implies bytes_model (r).count = Md5_output_bytes
		end

	sha256_path (a_path: PATH): detachable STRING
			-- SHA-256 hex of the file at `a_path'; Void if it cannot be read.
		require
			path_not_empty: not a_path.is_empty
		do
			Result := sha256_file (a_path.name)
		ensure
			correct_length: Result /= Void implies Result.count = Sha256_output_bytes * 2
		end

	sha512_path (a_path: PATH): detachable STRING
			-- SHA-512 hex of the file at `a_path'; Void if it cannot be read.
		require
			path_not_empty: not a_path.is_empty
		do
			Result := sha512_file (a_path.name)
		ensure
			correct_length: Result /= Void implies Result.count = Sha512_output_bytes * 2
		end

	sha1_path (a_path: PATH): detachable STRING
			-- SHA-1 hex of the file at `a_path'; Void if it cannot be read.
		require
			path_not_empty: not a_path.is_empty
		do
			Result := sha1_file (a_path.name)
		ensure
			correct_length: Result /= Void implies Result.count = Sha1_output_bytes * 2
		end

	md5_path (a_path: PATH): detachable STRING
			-- MD5 hex of the file at `a_path'; Void if it cannot be read.
		require
			path_not_empty: not a_path.is_empty
		do
			Result := md5_file (a_path.name)
		ensure
			correct_length: Result /= Void implies Result.count = Md5_output_bytes * 2
		end

feature -- Secure Comparison (Constant-Time)

	secure_compare (a_left, a_right: STRING): BOOLEAN
			-- Compare two strings in constant time to prevent timing attacks.
			-- Always compares all bytes regardless of where first difference occurs.
			-- Use this when comparing secrets like HMAC signatures, tokens, etc.
		local
			l_result: NATURAL_8
			i: INTEGER
		do
			-- Length difference check - but still compare to avoid timing leak
			if a_left.count /= a_right.count then
				-- Different lengths - compare anyway to maintain constant time
				-- but result will be False
				from
					i := 1
					l_result := 1 -- Mark as different
				until
					i > a_left.count.max (a_right.count)
				loop
					if i <= a_left.count and i <= a_right.count then
						l_result := l_result | (a_left [i].code.to_natural_8.bit_xor (a_right [i].code.to_natural_8))
					end
					i := i + 1
				variant
					a_left.count.max (a_right.count) + 1 - i
				end
			else
				-- Same length - XOR all bytes and accumulate
				from
					i := 1
					l_result := 0
				until
					i > a_left.count
				loop
					l_result := l_result | (a_left [i].code.to_natural_8.bit_xor (a_right [i].code.to_natural_8))
					i := i + 1
				variant
					a_left.count + 1 - i
				end
			end
			Result := l_result = 0
		ensure
			same_strings_equal: a_left.same_string (a_right) implies Result
			different_strings_unequal: not a_left.same_string (a_right) implies not Result
			symmetric: Result = secure_compare (a_right, a_left)
		end

	secure_compare_bytes (a_left, a_right: ARRAY [NATURAL_8]): BOOLEAN
			-- Compare two byte arrays in constant time to prevent timing attacks.
			-- Always compares all bytes regardless of where first difference occurs.
			-- Use this when comparing hash digests, HMAC values, etc.
		local
			l_result: NATURAL_8
			i: INTEGER
		do
			-- Length difference check
			if a_left.count /= a_right.count then
				-- Different lengths - still iterate to maintain timing consistency
				from
					i := 1
					l_result := 1
				until
					i > a_left.count.max (a_right.count)
				loop
					if i <= a_left.count and i <= a_right.count then
						l_result := l_result | (a_left [i].bit_xor (a_right [i]))
					end
					i := i + 1
				variant
					a_left.count.max (a_right.count) + 1 - i
				end
			else
				-- Same length - XOR all bytes and accumulate
				from
					i := 1
					l_result := 0
				until
					i > a_left.count
				loop
					l_result := l_result | (a_left [i].bit_xor (a_right [i]))
					i := i + 1
				variant
					a_left.count + 1 - i
				end
			end
			Result := l_result = 0
		ensure
			model_equal_implies_result: (bytes_model (a_left) |=| bytes_model (a_right)) implies Result
			symmetric: Result = secure_compare_bytes (a_right, a_left)
		end

	secure_compare_hex (a_left, a_right: STRING): BOOLEAN
			-- Compare two hex strings in constant time.
			-- Convenience wrapper - converts to bytes first for proper comparison.
		require
			left_valid_hex: a_left.count \\ 2 = 0 and across a_left as c all Hex_chars.has (c.item.as_lower) end
			right_valid_hex: a_right.count \\ 2 = 0 and across a_right as c all Hex_chars.has (c.item.as_lower) end
		do
			Result := secure_compare_bytes (hex_to_bytes (a_left), hex_to_bytes (a_right))
		ensure
			symmetric: Result = secure_compare_hex (a_right, a_left)
		end

feature -- Utilities

	bytes_to_hex (a_bytes: ARRAY [NATURAL_8]): STRING
			-- Convert bytes to lowercase hex string.
		do
			create Result.make (a_bytes.count * 2)
			across a_bytes as b loop
				Result.append (byte_to_hex (b.item))
			end
		ensure
			correct_length: Result.count = a_bytes.count * 2
			lowercase_hex: across Result as c all c.item.is_lower or c.item.is_digit end
			roundtrip: bytes_model (hex_to_bytes (Result)) |=| bytes_model (a_bytes)
		end

	hex_to_bytes (a_hex: STRING): ARRAY [NATURAL_8]
			-- Convert hex string to bytes.
		require
			even_length: a_hex.count \\ 2 = 0
			valid_hex: across a_hex as c all Hex_chars.has (c.item.as_lower) end
		local
			i: INTEGER
			l_result: ARRAYED_LIST [NATURAL_8]
		do
			create l_result.make (a_hex.count // 2)
			from i := 1 until i > a_hex.count loop
				l_result.extend (hex_pair_to_byte (a_hex.substring (i, i + 1)))
				i := i + 2
			variant
				a_hex.count + 2 - i
			end
			create Result.make_from_array (l_result.to_array)
		ensure
			correct_length: Result.count = a_hex.count // 2
			model_length: bytes_model (Result).count = a_hex.count // 2
		end

feature {NONE} -- Implementation: Streaming

	string_digest (a_state: SIMPLE_HASH_STATE; a_input: STRING): ARRAY [NATURAL_8]
			-- Digest of `a_input' through the fresh `a_state'.
		require
			fresh_state: a_state.byte_count = 0 and not a_state.is_finished
		do
			a_state.update (a_input)
			a_state.finish
			Result := a_state.digest
		ensure
			sized: Result.count = a_state.digest_size
		end

	file_digest (a_state: SIMPLE_HASH_STATE; a_name: NATIVE_STRING): detachable ARRAY [NATURAL_8]
			-- Digest of the file named `a_name', streamed through the fresh `a_state'
			-- in `File_chunk_size' pieces; Void if it cannot be opened or a read fails.
		require
			fresh_state: a_state.byte_count = 0 and not a_state.is_finished
		local
			l_handle: POINTER
			l_buffer: MANAGED_POINTER
			l_got: INTEGER
		do
			l_handle := c_open_for_read (a_name.item)
			if l_handle /= default_pointer then
				l_buffer := file_buffer
					-- No variant: the file may grow while it is read; each pass reads
					-- at least one byte and the loop ends at end of file or on error.
				from
					l_got := c_read (l_handle, l_buffer.item, l_buffer.count)
				until
					l_got <= 0
				loop
					a_state.update_from_managed (l_buffer, l_got)
					l_got := c_read (l_handle, l_buffer.item, l_buffer.count)
				end
				c_close (l_handle)
				l_handle := default_pointer
				if l_got = 0 then
					a_state.finish
					Result := a_state.digest
				end
			end
		ensure
			sized: attached Result as al_r implies al_r.count = a_state.digest_size
		rescue
			if l_handle /= default_pointer then
				c_close (l_handle)
			end
		end

	file_buffer: MANAGED_POINTER
			-- Reusable C-heap read buffer of `File_chunk_size' bytes.
		do
			if attached file_buffer_cache as al_buffer then
				Result := al_buffer
			else
				create Result.make (File_chunk_size)
				file_buffer_cache := Result
			end
		ensure
			sized: Result.count = File_chunk_size
		end

	file_buffer_cache: detachable MANAGED_POINTER
			-- Storage for `file_buffer', created on first file hash.

	hex_or_void (a_bytes: detachable ARRAY [NATURAL_8]): detachable STRING
			-- `a_bytes' as lowercase hex, or Void.
		do
			if attached a_bytes as al_bytes then
				Result := bytes_to_hex (al_bytes)
			end
		ensure
			void_kept: a_bytes = Void implies Result = Void
			hex_length: attached a_bytes as al_b implies (attached Result as al_r and then al_r.count = al_b.count * 2)
		end

feature {NONE} -- Implementation: Win32 file reading

	c_open_for_read (a_name: POINTER): POINTER
			-- Handle on the file at the UTF-16 path `a_name' opened for sequential
			-- reading (others may still read, write or delete it), or null.
			-- Blocking: an open can wait on the disk, the network or a virus scanner.
		external
			"C blocking inline use <windows.h>"
		alias
			"[
				HANDLE h = CreateFileW ((LPCWSTR) $a_name, GENERIC_READ,
					FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
					OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
				return (h == INVALID_HANDLE_VALUE) ? NULL : (EIF_POINTER) h;
			]"
		end

	c_read (a_handle, a_buffer: POINTER; a_count: INTEGER): INTEGER
			-- Read up to `a_count' bytes into the C-heap `a_buffer':
			-- bytes read, 0 at end of file, -1 on error.
			-- Blocking: a read waits on I/O.
		external
			"C blocking inline use <windows.h>"
		alias
			"[
				DWORD got = 0;
				if (!ReadFile ((HANDLE) $a_handle, (LPVOID) $a_buffer, (DWORD) $a_count, &got, NULL)) {
					return -1;
				}
				return (EIF_INTEGER) got;
			]"
		end

	c_close (a_handle: POINTER)
			-- Close `a_handle'.
		external
			"C inline use <windows.h>"
		alias
			"CloseHandle ((HANDLE) $a_handle);"
		end

feature {NONE} -- Implementation: Byte conversion

	string_to_bytes (a_string: STRING): ARRAY [NATURAL_8]
			-- Convert string to byte array.
		local
			i: INTEGER
		do
			create Result.make_filled (0, 1, a_string.count)
			from i := 1 until i > a_string.count loop
				Result [i] := a_string.code (i).to_natural_8
				i := i + 1
			variant
				a_string.count + 1 - i
			end
		ensure
			same_count: Result.count = a_string.count
		end

	byte_to_hex (a_byte: NATURAL_8): STRING
			-- Convert byte to 2-character lowercase hex.
		do
			create Result.make (2)
			Result.append_character (Hex_chars [(a_byte |>> 4).to_integer_32 + 1])
			Result.append_character (Hex_chars [(a_byte & 0x0F).to_integer_32 + 1])
		ensure
			correct_length: Result.count = 2
		end

	hex_pair_to_byte (a_hex: STRING): NATURAL_8
			-- Convert 2-character hex string to byte.
		require
			correct_length: a_hex.count = 2
		local
			high, low: INTEGER
		do
			high := Hex_chars.index_of (a_hex [1].as_lower, 1) - 1
			low := Hex_chars.index_of (a_hex [2].as_lower, 1) - 1
			if high >= 0 and low >= 0 then
				Result := ((high |<< 4) | low).to_natural_8
			end
		end

feature {NONE} -- Implementation

	working_buffer: ARRAY [NATURAL_32]
			-- Working buffer for hash computation.

feature -- Constants

	Hex_chars: STRING = "0123456789abcdef"
			-- Hexadecimal characters.

	File_buffer_size: INTEGER = 8192
			-- Former buffer size for file reading (8 KB chunks); kept for compatibility.
			-- File hashing now reads `File_chunk_size' at a time.

	File_chunk_size: INTEGER = 262144
			-- Bytes read per chunk when hashing a file (256 KB, one reusable C-heap buffer).

	Sha1_output_bytes: INTEGER = 20
			-- SHA-1 produces 20 bytes (160 bits).

	Sha256_output_bytes: INTEGER = 32
			-- SHA-256 produces 32 bytes (256 bits).

	Sha512_output_bytes: INTEGER = 64
			-- SHA-512 produces 64 bytes (512 bits).

	Md5_output_bytes: INTEGER = 16
			-- MD5 produces 16 bytes (128 bits).

feature -- Model Queries (MML)

	bytes_model (a_bytes: ARRAY [NATURAL_8]): MML_SEQUENCE [NATURAL_8]
			-- Mathematical model of byte array as an immutable sequence.
		do
			create Result
			across a_bytes as ic loop
				Result := Result & ic
			end
		ensure
			same_count: Result.count = a_bytes.count
			same_elements: across 1 |..| a_bytes.count as i all Result [i] = a_bytes [i] end
		end

	string_bytes_model (a_string: STRING): MML_SEQUENCE [NATURAL_8]
			-- Mathematical model of string as a byte sequence.
		do
			create Result
			across a_string as c loop
				Result := Result & c.item.code.to_natural_8
			end
		ensure
			same_count: Result.count = a_string.count
		end

	hex_model (a_hex: STRING): MML_SET [CHARACTER]
			-- Set of unique characters in a hex string (for verification).
		do
			create Result
			across a_hex as c loop
				Result := Result & c.item
			end
		ensure
			all_hex_chars: Result.for_all (agent (ch: CHARACTER): BOOLEAN do Result := Hex_chars.has (ch) end)
		end

invariant
	buffer_exists: working_buffer /= Void
	buffer_size: working_buffer.count = 64

note
	copyright: "Copyright (c) 2024-2025, Larry Rix"
	license: "MIT License"

end
