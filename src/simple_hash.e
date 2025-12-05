note
	description: "[
		Simple Hash - Lightweight cryptographic hashing for Eiffel.

		Supports:
		- SHA-256 - Secure hash, 256-bit output
		- HMAC-SHA256 - Keyed-hash message authentication
		- MD5 - Legacy hash (not for security, for checksums only)

		Usage:
			create hasher.make
			digest := hasher.sha256 ("Hello, World!")
			hmac := hasher.hmac_sha256 ("secret", "message")
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
			result_not_void: Result /= Void
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
				end

				-- Add compressed chunk to hash values
				h0 := h0 + a; h1 := h1 + b; h2 := h2 + c; h3 := h3 + d
				h4 := h4 + e; h5 := h5 + f; h6 := h6 + g; h7 := h7 + h

				chunk_start := chunk_start + 64
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
			result_not_void: Result /= Void
			correct_length: Result.count = 32
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
			result_not_void: Result /= Void
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
			end

			-- Create inner and outer padded keys
			create l_inner_pad.make_filled (0, 1, 64)
			create l_outer_pad.make_filled (0, 1, 64)
			from i := 1 until i > 64 loop
				l_inner_pad [i] := l_key_padded [i].bit_xor (0x36) -- ipad
				l_outer_pad [i] := l_key_padded [i].bit_xor (0x5c) -- opad
				i := i + 1
			end

			-- Inner hash: H((K' xor ipad) || m)
			l_inner_data := bytes_to_string (l_inner_pad) + a_message
			l_inner_hash := sha256_bytes (l_inner_data)

			-- Outer hash: H((K' xor opad) || inner_hash)
			l_outer_data := bytes_to_string (l_outer_pad) + bytes_to_string (l_inner_hash)
			Result := sha256_bytes (l_outer_data)
		ensure
			result_not_void: Result /= Void
			correct_length: Result.count = 32
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
			result_not_void: Result /= Void
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
				end

				a0 := a0 + a; b0 := b0 + b; c0 := c0 + c; d0 := d0 + d
				chunk_start := chunk_start + 64
			end

			-- Produce final hash (little-endian)
			create Result.make_filled (0, 1, 16)
			put_nat32_le (Result, 1, a0)
			put_nat32_le (Result, 5, b0)
			put_nat32_le (Result, 9, c0)
			put_nat32_le (Result, 13, d0)
		ensure
			result_not_void: Result /= Void
			correct_length: Result.count = 16
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
			result_not_void: Result /= Void
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
			end
			create Result.make_from_array (l_result.to_array)
		ensure
			result_not_void: Result /= Void
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
			end

			-- Append original length in bits as 64-bit big-endian
			from i := 56 until i < 0 loop
				l_result.extend ((l_len |>> i).to_natural_8 & 0xFF)
				i := i - 8
			end

			create Result.make_from_array (l_result.to_array)
		ensure
			result_not_void: Result /= Void
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
			end

			-- Append length in bits as 64-bit little-endian
			from i := 0 until i > 56 loop
				l_result.extend ((l_len |>> i).to_natural_8 & 0xFF)
				i := i + 8
			end

			create Result.make_from_array (l_result.to_array)
		ensure
			result_not_void: Result /= Void
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

feature {NONE} -- Implementation

	working_buffer: ARRAY [NATURAL_32]
			-- Working buffer for hash computation.

feature -- Constants

	Hex_chars: STRING = "0123456789abcdef"
			-- Hexadecimal characters.

invariant
	buffer_exists: working_buffer /= Void

note
	copyright: "Copyright (c) 2024-2025, Larry Rix"
	license: "MIT License"

end
