note
	description: "[
		Simple Hash - Lightweight cryptographic hashing for Eiffel.

		Supports:
		- SHA-256 - Secure hash, 256-bit output
		- HMAC-SHA256 - Keyed-hash message authentication
		- MD5 - Legacy hash (not for security, for checksums only)
		- Constant-time comparison - Prevents timing attacks

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

create
	make

feature {NONE} -- Initialization

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
		require
			input_not_void: a_input /= Void
		local
			l_bytes: ARRAY [NATURAL_8]
		do
			l_bytes := sha1_bytes (a_input)
			Result := bytes_to_hex (l_bytes)
		ensure
			correct_length: Result.count = 40
			lowercase_hex: across Result as c all c.item.is_lower or c.item.is_digit end
		end

	sha1_bytes (a_input: STRING): ARRAY [NATURAL_8]
			-- Compute SHA-1 hash of `a_input' and return as 20 bytes.
		require
			input_not_void: a_input /= Void
		local
			l_message: ARRAY [NATURAL_8]
			l_padded: ARRAY [NATURAL_8]
			h0, h1, h2, h3, h4: NATURAL_32
			a, b, c, d, e: NATURAL_32
			f, k, temp: NATURAL_32
			w: ARRAY [NATURAL_32]
			i, j, chunk_start: INTEGER
		do
			l_message := string_to_bytes (a_input)
			l_padded := sha256_pad (l_message)

			h0 := 0x67452301
			h1 := 0xEFCDAB89
			h2 := 0x98BADCFE
			h3 := 0x10325476
			h4 := 0xC3D2E1F0

			create w.make_filled (0, 1, 80)
			from chunk_start := 1 until chunk_start > l_padded.count loop
				from i := 1 until i > 16 loop
					j := chunk_start + (i - 1) * 4
					w [i] := (l_padded [j].to_natural_32 |<< 24) |
							 (l_padded [j + 1].to_natural_32 |<< 16) |
							 (l_padded [j + 2].to_natural_32 |<< 8) |
							 l_padded [j + 3].to_natural_32
					i := i + 1
				variant 17 - i end

				from i := 17 until i > 80 loop
					w [i] := rotl32 (w [i - 3].bit_xor (w [i - 8]).bit_xor (w [i - 14]).bit_xor (w [i - 16]), 1)
					i := i + 1
				variant 81 - i end

				a := h0; b := h1; c := h2; d := h3; e := h4

				from i := 1 until i > 80 loop
					if i <= 20 then
						f := (b & c) | (b.bit_not & d)
						k := 0x5A827999
					elseif i <= 40 then
						f := b.bit_xor (c).bit_xor (d)
						k := 0x6ED9EBA1
					elseif i <= 60 then
						f := (b & c) | (b & d) | (c & d)
						k := 0x8F1BBCDC
					else
						f := b.bit_xor (c).bit_xor (d)
						k := 0xCA62C1D6
					end
					temp := rotl32 (a, 5) + f + e + k + w [i]
					e := d; d := c; c := rotl32 (b, 30); b := a; a := temp
					i := i + 1
				variant 81 - i end

				h0 := h0 + a; h1 := h1 + b; h2 := h2 + c; h3 := h3 + d; h4 := h4 + e
				chunk_start := chunk_start + 64
			variant l_padded.count - chunk_start + 64 end

			create Result.make_filled (0, 1, 20)
			put_nat32_be (Result, 1, h0)
			put_nat32_be (Result, 5, h1)
			put_nat32_be (Result, 9, h2)
			put_nat32_be (Result, 13, h3)
			put_nat32_be (Result, 17, h4)
		ensure
			correct_length: Result.count = 20
		end

feature -- SHA-256

	sha256 (a_input: STRING): STRING
			-- Compute SHA-256 hash of `a_input' and return as hex string.
		require
			input_not_void: a_input /= Void
		local
			l_bytes: ARRAY [NATURAL_8]
		do
			l_bytes := sha256_bytes (a_input)
			Result := bytes_to_hex (l_bytes)
		ensure
			correct_length: Result.count = 64
			lowercase_hex: across Result as c all c.item.is_lower or c.item.is_digit end
		end

	sha256_bytes (a_input: STRING): ARRAY [NATURAL_8]
			-- Compute SHA-256 hash of `a_input' and return as 32 bytes.
		require
			input_not_void: a_input /= Void
		local
			l_message: ARRAY [NATURAL_8]
			l_padded: ARRAY [NATURAL_8]
			h0, h1, h2, h3, h4, h5, h6, h7: NATURAL_32
			a, b, c, d, e, f, g, h: NATURAL_32
			s0, s1, ch, maj, temp1, temp2: NATURAL_32
			w: ARRAY [NATURAL_32]
			i, j, chunk_start: INTEGER
		do
			-- Convert string to bytes
			l_message := string_to_bytes (a_input)

			-- Pad message
			l_padded := sha256_pad (l_message)

			-- Initialize hash values (first 32 bits of fractional parts of square roots of first 8 primes)
			h0 := 0x6a09e667
			h1 := 0xbb67ae85
			h2 := 0x3c6ef372
			h3 := 0xa54ff53a
			h4 := 0x510e527f
			h5 := 0x9b05688c
			h6 := 0x1f83d9ab
			h7 := 0x5be0cd19

			-- Process each 512-bit (64-byte) chunk
			create w.make_filled (0, 1, 64)
			from
				chunk_start := 1
			until
				chunk_start > l_padded.count
			loop
				-- Copy chunk into first 16 words
				from
					i := 1
				until
					i > 16
				loop
					j := chunk_start + (i - 1) * 4
					w [i] := (l_padded [j].to_natural_32 |<< 24) |
							 (l_padded [j + 1].to_natural_32 |<< 16) |
							 (l_padded [j + 2].to_natural_32 |<< 8) |
							 l_padded [j + 3].to_natural_32
					i := i + 1
				variant
					17 - i
				end

				-- Extend first 16 words into remaining 48 words
				from
					i := 17
				until
					i > 64
				loop
					s0 := rotr32 (w [i - 15], 7).bit_xor (rotr32 (w [i - 15], 18)).bit_xor (w [i - 15] |>> 3)
					s1 := rotr32 (w [i - 2], 17).bit_xor (rotr32 (w [i - 2], 19)).bit_xor (w [i - 2] |>> 10)
					w [i] := w [i - 16] + s0 + w [i - 7] + s1
					i := i + 1
				variant
					65 - i
				end

				-- Initialize working variables
				a := h0; b := h1; c := h2; d := h3
				e := h4; f := h5; g := h6; h := h7

				-- Main compression loop
				from
					i := 1
				until
					i > 64
				loop
					s1 := rotr32 (e, 6).bit_xor (rotr32 (e, 11)).bit_xor (rotr32 (e, 25))
					ch := (e & f).bit_xor (e.bit_not & g)
					temp1 := h + s1 + ch + sha256_k [i] + w [i]
					s0 := rotr32 (a, 2).bit_xor (rotr32 (a, 13)).bit_xor (rotr32 (a, 22))
					maj := (a & b).bit_xor (a & c).bit_xor (b & c)
					temp2 := s0 + maj

					h := g; g := f; f := e
					e := d + temp1
					d := c; c := b; b := a
					a := temp1 + temp2
					i := i + 1
				variant
					65 - i
				end

				-- Add compressed chunk to hash values
				h0 := h0 + a; h1 := h1 + b; h2 := h2 + c; h3 := h3 + d
				h4 := h4 + e; h5 := h5 + f; h6 := h6 + g; h7 := h7 + h

				chunk_start := chunk_start + 64
			variant
				l_padded.count - chunk_start + 64
			end

			-- Produce final hash value (big-endian)
			create Result.make_filled (0, 1, 32)
			put_nat32_be (Result, 1, h0)
			put_nat32_be (Result, 5, h1)
			put_nat32_be (Result, 9, h2)
			put_nat32_be (Result, 13, h3)
			put_nat32_be (Result, 17, h4)
			put_nat32_be (Result, 21, h5)
			put_nat32_be (Result, 25, h6)
			put_nat32_be (Result, 29, h7)
		ensure
			correct_length: Result.count = 32
		end

feature -- SHA-512

	sha512 (a_input: STRING): STRING
			-- Compute SHA-512 hash of `a_input' and return as hex string.
		require
			input_not_void: a_input /= Void
		local
			l_bytes: ARRAY [NATURAL_8]
		do
			l_bytes := sha512_bytes (a_input)
			Result := bytes_to_hex (l_bytes)
		ensure
			correct_length: Result.count = 128
			lowercase_hex: across Result as c all c.item.is_lower or c.item.is_digit end
		end

	sha512_bytes (a_input: STRING): ARRAY [NATURAL_8]
			-- Compute SHA-512 hash of `a_input' and return as 64 bytes.
		require
			input_not_void: a_input /= Void
		local
			l_message: ARRAY [NATURAL_8]
			l_padded: ARRAY [NATURAL_8]
			h0, h1, h2, h3, h4, h5, h6, h7: NATURAL_64
			a, b, c, d, e, f, g, h: NATURAL_64
			s0, s1, ch, maj, temp1, temp2: NATURAL_64
			w: ARRAY [NATURAL_64]
			i, j, chunk_start: INTEGER
		do
			-- Convert string to bytes
			l_message := string_to_bytes (a_input)

			-- Pad message
			l_padded := sha512_pad (l_message)

			-- Initialize hash values (first 64 bits of fractional parts of square roots of first 8 primes)
			h0 := 0x6a09e667f3bcc908
			h1 := 0xbb67ae8584caa73b
			h2 := 0x3c6ef372fe94f82b
			h3 := 0xa54ff53a5f1d36f1
			h4 := 0x510e527fade682d1
			h5 := 0x9b05688c2b3e6c1f
			h6 := 0x1f83d9abfb41bd6b
			h7 := 0x5be0cd19137e2179

			-- Process each 1024-bit (128-byte) chunk
			create w.make_filled (0, 1, 80)
			from
				chunk_start := 1
			until
				chunk_start > l_padded.count
			loop
				-- Copy chunk into first 16 words (64-bit each)
				from
					i := 1
				until
					i > 16
				loop
					j := chunk_start + (i - 1) * 8
					w [i] := (l_padded [j].to_natural_64 |<< 56) |
							 (l_padded [j + 1].to_natural_64 |<< 48) |
							 (l_padded [j + 2].to_natural_64 |<< 40) |
							 (l_padded [j + 3].to_natural_64 |<< 32) |
							 (l_padded [j + 4].to_natural_64 |<< 24) |
							 (l_padded [j + 5].to_natural_64 |<< 16) |
							 (l_padded [j + 6].to_natural_64 |<< 8) |
							 l_padded [j + 7].to_natural_64
					i := i + 1
				variant
					17 - i
				end

				-- Extend first 16 words into remaining 64 words
				from
					i := 17
				until
					i > 80
				loop
					s0 := rotr64 (w [i - 15], 1).bit_xor (rotr64 (w [i - 15], 8)).bit_xor (w [i - 15] |>> 7)
					s1 := rotr64 (w [i - 2], 19).bit_xor (rotr64 (w [i - 2], 61)).bit_xor (w [i - 2] |>> 6)
					w [i] := w [i - 16] + s0 + w [i - 7] + s1
					i := i + 1
				variant
					81 - i
				end

				-- Initialize working variables
				a := h0; b := h1; c := h2; d := h3
				e := h4; f := h5; g := h6; h := h7

				-- Main compression loop (80 rounds)
				from
					i := 1
				until
					i > 80
				loop
					s1 := rotr64 (e, 14).bit_xor (rotr64 (e, 18)).bit_xor (rotr64 (e, 41))
					ch := (e & f).bit_xor (e.bit_not & g)
					temp1 := h + s1 + ch + sha512_k [i] + w [i]
					s0 := rotr64 (a, 28).bit_xor (rotr64 (a, 34)).bit_xor (rotr64 (a, 39))
					maj := (a & b).bit_xor (a & c).bit_xor (b & c)
					temp2 := s0 + maj

					h := g; g := f; f := e
					e := d + temp1
					d := c; c := b; b := a
					a := temp1 + temp2
					i := i + 1
				variant
					81 - i
				end

				-- Add compressed chunk to hash values
				h0 := h0 + a; h1 := h1 + b; h2 := h2 + c; h3 := h3 + d
				h4 := h4 + e; h5 := h5 + f; h6 := h6 + g; h7 := h7 + h

				chunk_start := chunk_start + 128
			variant
				l_padded.count - chunk_start + 128
			end

			-- Produce final hash value (big-endian)
			create Result.make_filled (0, 1, 64)
			put_nat64_be (Result, 1, h0)
			put_nat64_be (Result, 9, h1)
			put_nat64_be (Result, 17, h2)
			put_nat64_be (Result, 25, h3)
			put_nat64_be (Result, 33, h4)
			put_nat64_be (Result, 41, h5)
			put_nat64_be (Result, 49, h6)
			put_nat64_be (Result, 57, h7)
		ensure
			correct_length: Result.count = 64
		end

feature -- HMAC-SHA256

	hmac_sha256 (a_key, a_message: STRING): STRING
			-- Compute HMAC-SHA256 of `a_message' using `a_key', return as hex string.
		require
			key_not_void: a_key /= Void
			message_not_void: a_message /= Void
		local
			l_bytes: ARRAY [NATURAL_8]
		do
			l_bytes := hmac_sha256_bytes (a_key, a_message)
			Result := bytes_to_hex (l_bytes)
		ensure
			correct_length: Result.count = 64
		end

	hmac_sha256_bytes (a_key, a_message: STRING): ARRAY [NATURAL_8]
			-- Compute HMAC-SHA256 of `a_message' using `a_key', return as 32 bytes.
			-- HMAC(K, m) = H((K' xor opad) || H((K' xor ipad) || m))
		require
			key_not_void: a_key /= Void
			message_not_void: a_message /= Void
		local
			l_key_bytes: ARRAY [NATURAL_8]
			l_key_padded: ARRAY [NATURAL_8]
			l_inner_pad, l_outer_pad: ARRAY [NATURAL_8]
			l_inner_data, l_outer_data: STRING
			l_inner_hash: ARRAY [NATURAL_8]
			i: INTEGER
		do
			-- Get key bytes
			l_key_bytes := string_to_bytes (a_key)

			-- If key is longer than block size (64 bytes), hash it
			if l_key_bytes.count > 64 then
				l_key_bytes := sha256_bytes (a_key)
			end

			-- Pad key to 64 bytes
			create l_key_padded.make_filled (0, 1, 64)
			from i := 1 until i > l_key_bytes.count loop
				l_key_padded [i] := l_key_bytes [i]
				i := i + 1
			variant
				l_key_bytes.count + 1 - i
			end

			-- Create inner and outer padded keys
			create l_inner_pad.make_filled (0, 1, 64)
			create l_outer_pad.make_filled (0, 1, 64)
			from i := 1 until i > 64 loop
				l_inner_pad [i] := l_key_padded [i].bit_xor (0x36) -- ipad
				l_outer_pad [i] := l_key_padded [i].bit_xor (0x5c) -- opad
				i := i + 1
			variant
				65 - i
			end

			-- Inner hash: H((K' xor ipad) || m)
			l_inner_data := bytes_to_string (l_inner_pad) + a_message
			l_inner_hash := sha256_bytes (l_inner_data)

			-- Outer hash: H((K' xor opad) || inner_hash)
			l_outer_data := bytes_to_string (l_outer_pad) + bytes_to_string (l_inner_hash)
			Result := sha256_bytes (l_outer_data)
		ensure
			correct_length: Result.count = 32
		end

feature -- HMAC-SHA512

	hmac_sha512 (a_key, a_message: STRING): STRING
			-- Compute HMAC-SHA512 of `a_message' using `a_key', return as hex string.
		require
			key_not_void: a_key /= Void
			message_not_void: a_message /= Void
		local
			l_bytes: ARRAY [NATURAL_8]
		do
			l_bytes := hmac_sha512_bytes (a_key, a_message)
			Result := bytes_to_hex (l_bytes)
		ensure
			correct_length: Result.count = 128
		end

	hmac_sha512_bytes (a_key, a_message: STRING): ARRAY [NATURAL_8]
			-- Compute HMAC-SHA512 of `a_message' using `a_key', return as 64 bytes.
			-- HMAC(K, m) = H((K' xor opad) || H((K' xor ipad) || m))
			-- Block size for SHA-512 is 128 bytes.
		require
			key_not_void: a_key /= Void
			message_not_void: a_message /= Void
		local
			l_key_bytes: ARRAY [NATURAL_8]
			l_key_padded: ARRAY [NATURAL_8]
			l_inner_pad, l_outer_pad: ARRAY [NATURAL_8]
			l_inner_data, l_outer_data: STRING
			l_inner_hash: ARRAY [NATURAL_8]
			i: INTEGER
		do
			-- Get key bytes
			l_key_bytes := string_to_bytes (a_key)

			-- If key is longer than block size (128 bytes for SHA-512), hash it
			if l_key_bytes.count > 128 then
				l_key_bytes := sha512_bytes (a_key)
			end

			-- Pad key to 128 bytes
			create l_key_padded.make_filled (0, 1, 128)
			from i := 1 until i > l_key_bytes.count loop
				l_key_padded [i] := l_key_bytes [i]
				i := i + 1
			variant
				l_key_bytes.count + 1 - i
			end

			-- Create inner and outer padded keys
			create l_inner_pad.make_filled (0, 1, 128)
			create l_outer_pad.make_filled (0, 1, 128)
			from i := 1 until i > 128 loop
				l_inner_pad [i] := l_key_padded [i].bit_xor (0x36) -- ipad
				l_outer_pad [i] := l_key_padded [i].bit_xor (0x5c) -- opad
				i := i + 1
			variant
				129 - i
			end

			-- Inner hash: H((K' xor ipad) || m)
			l_inner_data := bytes_to_string (l_inner_pad) + a_message
			l_inner_hash := sha512_bytes (l_inner_data)

			-- Outer hash: H((K' xor opad) || inner_hash)
			l_outer_data := bytes_to_string (l_outer_pad) + bytes_to_string (l_inner_hash)
			Result := sha512_bytes (l_outer_data)
		ensure
			correct_length: Result.count = 64
		end

feature -- MD5 (Legacy - not for security)

	md5 (a_input: STRING): STRING
			-- Compute MD5 hash of `a_input' and return as hex string.
			-- WARNING: MD5 is cryptographically broken. Use for checksums only.
		require
			input_not_void: a_input /= Void
		local
			l_bytes: ARRAY [NATURAL_8]
		do
			l_bytes := md5_bytes (a_input)
			Result := bytes_to_hex (l_bytes)
		ensure
			correct_length: Result.count = 32
		end

	md5_bytes (a_input: STRING): ARRAY [NATURAL_8]
			-- Compute MD5 hash of `a_input' and return as 16 bytes.
		require
			input_not_void: a_input /= Void
		local
			l_message: ARRAY [NATURAL_8]
			l_padded: ARRAY [NATURAL_8]
			a0, b0, c0, d0: NATURAL_32
			a, b, c, d, f, g_val: NATURAL_32
			temp: NATURAL_32
			m: ARRAY [NATURAL_32]
			i, j, chunk_start: INTEGER
		do
			l_message := string_to_bytes (a_input)
			l_padded := md5_pad (l_message)

			-- Initialize variables
			a0 := 0x67452301
			b0 := 0xefcdab89
			c0 := 0x98badcfe
			d0 := 0x10325476

			create m.make_filled (0, 1, 16)

			from chunk_start := 1 until chunk_start > l_padded.count loop
				-- Break chunk into 16 32-bit words (little-endian)
				from i := 1 until i > 16 loop
					j := chunk_start + (i - 1) * 4
					m [i] := l_padded [j].to_natural_32 |
							(l_padded [j + 1].to_natural_32 |<< 8) |
							(l_padded [j + 2].to_natural_32 |<< 16) |
							(l_padded [j + 3].to_natural_32 |<< 24)
					i := i + 1
				variant
					17 - i
				end

				a := a0; b := b0; c := c0; d := d0

				from i := 0 until i > 63 loop
					if i <= 15 then
						f := (b & c) | (b.bit_not & d)
						g_val := i.to_natural_32
					elseif i <= 31 then
						f := (d & b) | (d.bit_not & c)
						g_val := ((5 * i + 1) \\ 16).to_natural_32
					elseif i <= 47 then
						f := b.bit_xor (c).bit_xor (d)
						g_val := ((3 * i + 5) \\ 16).to_natural_32
					else
						f := c.bit_xor (b | d.bit_not)
						g_val := ((7 * i) \\ 16).to_natural_32
					end

					temp := d
					d := c
					c := b
					b := b + rotl32 (a + f + md5_k [i + 1] + m [g_val.to_integer_32 + 1], md5_s [i + 1])
					a := temp
					i := i + 1
				variant
					64 - i
				end

				a0 := a0 + a; b0 := b0 + b; c0 := c0 + c; d0 := d0 + d
				chunk_start := chunk_start + 64
			variant
				l_padded.count - chunk_start + 64
			end

			-- Produce final hash (little-endian)
			create Result.make_filled (0, 1, 16)
			put_nat32_le (Result, 1, a0)
			put_nat32_le (Result, 5, b0)
			put_nat32_le (Result, 9, c0)
			put_nat32_le (Result, 13, d0)
		ensure
			correct_length: Result.count = 16
		end

feature -- File Hashing

	sha256_file (a_path: STRING): detachable STRING
			-- Compute SHA-256 hash of file at `a_path' and return as hex string.
			-- Returns Void if file cannot be read.
		require
			path_not_void: a_path /= Void
			path_not_empty: not a_path.is_empty
		local
			l_bytes: detachable ARRAY [NATURAL_8]
		do
			l_bytes := sha256_file_bytes (a_path)
			if l_bytes /= Void then
				Result := bytes_to_hex (l_bytes)
			end
		ensure
			correct_length: Result /= Void implies Result.count = 64
		end

	sha256_file_bytes (a_path: STRING): detachable ARRAY [NATURAL_8]
			-- Compute SHA-256 hash of file at `a_path' and return as 32 bytes.
			-- Returns Void if file cannot be read.
		require
			path_not_void: a_path /= Void
			path_not_empty: not a_path.is_empty
		local
			l_file: RAW_FILE
			l_content: STRING
		do
			create l_file.make_with_name (a_path)
			if l_file.exists and then l_file.is_readable then
				l_file.open_read
				create l_content.make_empty
				from until l_file.end_of_file loop
					l_file.read_stream (File_buffer_size)
					l_content.append (l_file.last_string)
				end
				l_file.close
				Result := sha256_bytes (l_content)
			end
		ensure
			correct_length: Result /= Void implies Result.count = 32
		end

	sha512_file (a_path: STRING): detachable STRING
			-- Compute SHA-512 hash of file at `a_path' and return as hex string.
			-- Returns Void if file cannot be read.
		require
			path_not_void: a_path /= Void
			path_not_empty: not a_path.is_empty
		local
			l_bytes: detachable ARRAY [NATURAL_8]
		do
			l_bytes := sha512_file_bytes (a_path)
			if l_bytes /= Void then
				Result := bytes_to_hex (l_bytes)
			end
		ensure
			correct_length: Result /= Void implies Result.count = 128
		end

	sha512_file_bytes (a_path: STRING): detachable ARRAY [NATURAL_8]
			-- Compute SHA-512 hash of file at `a_path' and return as 64 bytes.
			-- Returns Void if file cannot be read.
		require
			path_not_void: a_path /= Void
			path_not_empty: not a_path.is_empty
		local
			l_file: RAW_FILE
			l_content: STRING
		do
			create l_file.make_with_name (a_path)
			if l_file.exists and then l_file.is_readable then
				l_file.open_read
				create l_content.make_empty
				from until l_file.end_of_file loop
					l_file.read_stream (File_buffer_size)
					l_content.append (l_file.last_string)
				end
				l_file.close
				Result := sha512_bytes (l_content)
			end
		ensure
			correct_length: Result /= Void implies Result.count = 64
		end

	md5_file (a_path: STRING): detachable STRING
			-- Compute MD5 hash of file at `a_path' and return as hex string.
			-- Returns Void if file cannot be read.
			-- WARNING: MD5 is cryptographically broken. Use for checksums only.
		require
			path_not_void: a_path /= Void
			path_not_empty: not a_path.is_empty
		local
			l_bytes: detachable ARRAY [NATURAL_8]
		do
			l_bytes := md5_file_bytes (a_path)
			if l_bytes /= Void then
				Result := bytes_to_hex (l_bytes)
			end
		ensure
			correct_length: Result /= Void implies Result.count = 32
		end

	md5_file_bytes (a_path: STRING): detachable ARRAY [NATURAL_8]
			-- Compute MD5 hash of file at `a_path' and return as 16 bytes.
			-- Returns Void if file cannot be read.
		require
			path_not_void: a_path /= Void
			path_not_empty: not a_path.is_empty
		local
			l_file: RAW_FILE
			l_content: STRING
		do
			create l_file.make_with_name (a_path)
			if l_file.exists and then l_file.is_readable then
				l_file.open_read
				create l_content.make_empty
				from until l_file.end_of_file loop
					l_file.read_stream (File_buffer_size)
					l_content.append (l_file.last_string)
				end
				l_file.close
				Result := md5_bytes (l_content)
			end
		ensure
			correct_length: Result /= Void implies Result.count = 16
		end

feature -- Secure Comparison (Constant-Time)

	secure_compare (a_left, a_right: STRING): BOOLEAN
			-- Compare two strings in constant time to prevent timing attacks.
			-- Always compares all bytes regardless of where first difference occurs.
			-- Use this when comparing secrets like HMAC signatures, tokens, etc.
		require
			left_not_void: a_left /= Void
			right_not_void: a_right /= Void
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
		end

	secure_compare_bytes (a_left, a_right: ARRAY [NATURAL_8]): BOOLEAN
			-- Compare two byte arrays in constant time to prevent timing attacks.
			-- Always compares all bytes regardless of where first difference occurs.
			-- Use this when comparing hash digests, HMAC values, etc.
		require
			left_not_void: a_left /= Void
			right_not_void: a_right /= Void
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
		end

	secure_compare_hex (a_left, a_right: STRING): BOOLEAN
			-- Compare two hex strings in constant time.
			-- Convenience wrapper - converts to bytes first for proper comparison.
		require
			left_not_void: a_left /= Void
			right_not_void: a_right /= Void
			left_valid_hex: a_left.count \\ 2 = 0 and across a_left as c all Hex_chars.has (c.item.as_lower) end
			right_valid_hex: a_right.count \\ 2 = 0 and across a_right as c all Hex_chars.has (c.item.as_lower) end
		do
			Result := secure_compare_bytes (hex_to_bytes (a_left), hex_to_bytes (a_right))
		end

feature -- Utilities

	bytes_to_hex (a_bytes: ARRAY [NATURAL_8]): STRING
			-- Convert bytes to lowercase hex string.
		require
			bytes_not_void: a_bytes /= Void
		do
			create Result.make (a_bytes.count * 2)
			across a_bytes as b loop
				Result.append (byte_to_hex (b.item))
			end
		ensure
			correct_length: Result.count = a_bytes.count * 2
		end

	hex_to_bytes (a_hex: STRING): ARRAY [NATURAL_8]
			-- Convert hex string to bytes.
		require
			hex_not_void: a_hex /= Void
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
		end

feature {NONE} -- Implementation: SHA-256

	sha256_pad (a_message: ARRAY [NATURAL_8]): ARRAY [NATURAL_8]
			-- Pad message according to SHA-256 spec.
		local
			l_len: INTEGER_64
			l_padded_len: INTEGER
			i: INTEGER
			l_result: ARRAYED_LIST [NATURAL_8]
		do
			l_len := a_message.count.to_integer_64 * 8 -- length in bits

			-- Calculate padded length (multiple of 512 bits = 64 bytes)
			l_padded_len := a_message.count + 1 + 8 -- message + 0x80 + 64-bit length
			if l_padded_len \\ 64 /= 0 then
				l_padded_len := l_padded_len + (64 - l_padded_len \\ 64)
			end

			create l_result.make (l_padded_len)

			-- Copy original message
			across a_message as b loop
				l_result.extend (b.item)
			end

			-- Append bit '1' (0x80)
			l_result.extend (0x80)

			-- Append zeros until 8 bytes from end
			from until l_result.count = l_padded_len - 8 loop
				l_result.extend (0)
			variant
				l_padded_len - 8 - l_result.count
			end

			-- Append original length in bits as 64-bit big-endian
			from i := 56 until i < 0 loop
				l_result.extend ((l_len |>> i).to_natural_8 & 0xFF)
				i := i - 8
			variant
				i + 8
			end

			create Result.make_from_array (l_result.to_array)
		ensure
			multiple_of_64: Result.count \\ 64 = 0
		end

	sha256_k: ARRAY [NATURAL_32]
			-- SHA-256 round constants (first 32 bits of fractional parts of cube roots of first 64 primes).
		once
			Result := {ARRAY [NATURAL_32]} <<
				0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
				0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
				0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
				0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
				0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
				0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
				0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
				0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
			>>
		end

feature {NONE} -- Implementation: SHA-512

	sha512_pad (a_message: ARRAY [NATURAL_8]): ARRAY [NATURAL_8]
			-- Pad message according to SHA-512 spec.
			-- Block size is 1024 bits (128 bytes).
		local
			l_len: NATURAL_64
			l_padded_len: INTEGER
			i: INTEGER
			l_result: ARRAYED_LIST [NATURAL_8]
		do
			l_len := a_message.count.to_natural_64 * 8 -- length in bits

			-- Calculate padded length (multiple of 1024 bits = 128 bytes)
			l_padded_len := a_message.count + 1 + 16 -- message + 0x80 + 128-bit length
			if l_padded_len \\ 128 /= 0 then
				l_padded_len := l_padded_len + (128 - l_padded_len \\ 128)
			end

			create l_result.make (l_padded_len)

			-- Copy original message
			across a_message as b loop
				l_result.extend (b.item)
			end

			-- Append bit '1' (0x80)
			l_result.extend (0x80)

			-- Append zeros until 16 bytes from end
			from until l_result.count = l_padded_len - 16 loop
				l_result.extend (0)
			variant
				l_padded_len - 16 - l_result.count
			end

			-- Append original length in bits as 128-bit big-endian (high 64 bits are 0)
			from i := 1 until i > 8 loop
				l_result.extend (0)
				i := i + 1
			variant
				9 - i
			end
			from i := 56 until i < 0 loop
				l_result.extend ((l_len |>> i).to_natural_8 & 0xFF)
				i := i - 8
			variant
				i + 8
			end

			create Result.make_from_array (l_result.to_array)
		ensure
			multiple_of_128: Result.count \\ 128 = 0
		end

	sha512_k: ARRAY [NATURAL_64]
			-- SHA-512 round constants (first 64 bits of fractional parts of cube roots of first 80 primes).
		once
			Result := {ARRAY [NATURAL_64]} <<
				0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
				0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
				0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
				0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
				0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
				0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
				0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
				0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
				0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
				0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
				0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
				0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
				0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
				0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
				0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
				0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
				0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
				0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
				0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
				0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
			>>
		end

feature {NONE} -- Implementation: MD5

	md5_pad (a_message: ARRAY [NATURAL_8]): ARRAY [NATURAL_8]
			-- Pad message according to MD5 spec.
		local
			l_len: INTEGER_64
			l_padded_len: INTEGER
			i: INTEGER
			l_result: ARRAYED_LIST [NATURAL_8]
		do
			l_len := a_message.count.to_integer_64 * 8

			l_padded_len := a_message.count + 1 + 8
			if l_padded_len \\ 64 /= 0 then
				l_padded_len := l_padded_len + (64 - l_padded_len \\ 64)
			end

			create l_result.make (l_padded_len)
			across a_message as b loop
				l_result.extend (b.item)
			end
			l_result.extend (0x80)
			from until l_result.count = l_padded_len - 8 loop
				l_result.extend (0)
			variant
				l_padded_len - 8 - l_result.count
			end

			-- Append length in bits as 64-bit little-endian
			from i := 0 until i > 56 loop
				l_result.extend ((l_len |>> i).to_natural_8 & 0xFF)
				i := i + 8
			variant
				64 - i
			end

			create Result.make_from_array (l_result.to_array)
		ensure
			multiple_of_64: Result.count \\ 64 = 0
		end

	md5_k: ARRAY [NATURAL_32]
			-- MD5 constants (floor(2^32 * abs(sin(i + 1)))).
		once
			Result := {ARRAY [NATURAL_32]} <<
				0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
				0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
				0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
				0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
				0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
				0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
				0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
				0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
			>>
		end

	md5_s: ARRAY [INTEGER]
			-- MD5 shift amounts.
		once
			Result := <<
				7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
				5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
				4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
				6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
			>>
		end

feature {NONE} -- Implementation: Bit operations

	rotr32 (a_value: NATURAL_32; a_shift: INTEGER): NATURAL_32
			-- Rotate right 32-bit.
		require
			valid_shift: a_shift >= 0 and a_shift < 32
		do
			Result := (a_value |>> a_shift) | (a_value |<< (32 - a_shift))
		end

	rotl32 (a_value: NATURAL_32; a_shift: INTEGER): NATURAL_32
			-- Rotate left 32-bit.
		require
			valid_shift: a_shift >= 0 and a_shift < 32
		do
			Result := (a_value |<< a_shift) | (a_value |>> (32 - a_shift))
		end

	rotr64 (a_value: NATURAL_64; a_shift: INTEGER): NATURAL_64
			-- Rotate right 64-bit.
		require
			valid_shift: a_shift >= 0 and a_shift < 64
		do
			Result := (a_value |>> a_shift) | (a_value |<< (64 - a_shift))
		end

feature {NONE} -- Implementation: Byte conversion

	string_to_bytes (a_string: STRING): ARRAY [NATURAL_8]
			-- Convert string to byte array.
		local
			l_result: ARRAYED_LIST [NATURAL_8]
		do
			create l_result.make (a_string.count)
			across a_string as c loop
				l_result.extend (c.item.code.to_natural_8)
			end
			create Result.make_from_array (l_result.to_array)
		end

	bytes_to_string (a_bytes: ARRAY [NATURAL_8]): STRING
			-- Convert byte array to string.
		do
			create Result.make (a_bytes.count)
			across a_bytes as b loop
				Result.append_character (b.item.to_character_8)
			end
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

	put_nat32_be (a_array: ARRAY [NATURAL_8]; a_index: INTEGER; a_value: NATURAL_32)
			-- Put 32-bit value in big-endian order.
		require
			valid_index: a_index >= 1 and a_index + 3 <= a_array.count
		do
			a_array [a_index] := (a_value |>> 24).to_natural_8
			a_array [a_index + 1] := (a_value |>> 16).to_natural_8
			a_array [a_index + 2] := (a_value |>> 8).to_natural_8
			a_array [a_index + 3] := a_value.to_natural_8
		end

	put_nat32_le (a_array: ARRAY [NATURAL_8]; a_index: INTEGER; a_value: NATURAL_32)
			-- Put 32-bit value in little-endian order.
		require
			valid_index: a_index >= 1 and a_index + 3 <= a_array.count
		do
			a_array [a_index] := a_value.to_natural_8
			a_array [a_index + 1] := (a_value |>> 8).to_natural_8
			a_array [a_index + 2] := (a_value |>> 16).to_natural_8
			a_array [a_index + 3] := (a_value |>> 24).to_natural_8
		end

	put_nat64_be (a_array: ARRAY [NATURAL_8]; a_index: INTEGER; a_value: NATURAL_64)
			-- Put 64-bit value in big-endian order.
		require
			valid_index: a_index >= 1 and a_index + 7 <= a_array.count
		do
			a_array [a_index] := (a_value |>> 56).to_natural_8
			a_array [a_index + 1] := (a_value |>> 48).to_natural_8
			a_array [a_index + 2] := (a_value |>> 40).to_natural_8
			a_array [a_index + 3] := (a_value |>> 32).to_natural_8
			a_array [a_index + 4] := (a_value |>> 24).to_natural_8
			a_array [a_index + 5] := (a_value |>> 16).to_natural_8
			a_array [a_index + 6] := (a_value |>> 8).to_natural_8
			a_array [a_index + 7] := a_value.to_natural_8
		end

feature {NONE} -- Implementation

	working_buffer: ARRAY [NATURAL_32]
			-- Working buffer for hash computation.

feature -- Constants

	Hex_chars: STRING = "0123456789abcdef"
			-- Hexadecimal characters.

	File_buffer_size: INTEGER = 8192
			-- Buffer size for file reading (8 KB chunks).

invariant
	buffer_exists: working_buffer /= Void

note
	copyright: "Copyright (c) 2024-2025, Larry Rix"
	license: "MIT License"

end
