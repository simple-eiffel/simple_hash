note
	description: "[
		Streaming MD5 (RFC 1321). 64-byte blocks, 16-byte digest,
		little-endian length field and digest.
		MD5 is cryptographically broken: use it for checksums only.
		See SIMPLE_HASH_STATE for the feeding protocol.
	]"
	author: "Larry Rix"
	date: "$Date$"
	revision: "$Revision$"
	EIS: "name=RFC 1321", "src=https://www.rfc-editor.org/rfc/rfc1321", "protocol=URI", "tag=specification"

class
	SIMPLE_MD5_STATE

inherit
	SIMPLE_HASH_STATE

create
	make

feature -- Measurement

	block_size: INTEGER = 64
			-- <Precursor>

	digest_size: INTEGER = 16
			-- <Precursor>

feature {NONE} -- Implementation

	chaining_size: INTEGER = 16
			-- <Precursor>

	length_field_size: INTEGER = 8
			-- <Precursor>

	is_length_big_endian: BOOLEAN = False
			-- <Precursor>

	load_initial_chaining
			-- <Precursor>
		do
			chaining.put_natural_32 (0x67452301, 0)
			chaining.put_natural_32 (0xefcdab89, 4)
			chaining.put_natural_32 (0x98badcfe, 8)
			chaining.put_natural_32 (0x10325476, 12)
		end

	chaining_digest: ARRAY [NATURAL_8]
			-- <Precursor>
		local
			i: INTEGER
			l_word: NATURAL_32
		do
			create Result.make_filled (0, 1, digest_size)
			from i := 0 until i = 4 loop
				l_word := chaining.read_natural_32 (i * 4)
				Result [i * 4 + 1] := l_word.to_natural_8
				Result [i * 4 + 2] := (l_word |>> 8).to_natural_8
				Result [i * 4 + 3] := (l_word |>> 16).to_natural_8
				Result [i * 4 + 4] := (l_word |>> 24).to_natural_8
				i := i + 1
			variant
				4 - i
			end
		end

	compress_blocks (a_state, a_data: POINTER; a_blocks: INTEGER)
			-- <Precursor>
		external
			"C blocking inline"
		alias
			"[
				static const EIF_NATURAL_32 K[64] = {
					0xd76aa478U, 0xe8c7b756U, 0x242070dbU, 0xc1bdceeeU, 0xf57c0fafU, 0x4787c62aU, 0xa8304613U, 0xfd469501U,
					0x698098d8U, 0x8b44f7afU, 0xffff5bb1U, 0x895cd7beU, 0x6b901122U, 0xfd987193U, 0xa679438eU, 0x49b40821U,
					0xf61e2562U, 0xc040b340U, 0x265e5a51U, 0xe9b6c7aaU, 0xd62f105dU, 0x02441453U, 0xd8a1e681U, 0xe7d3fbc8U,
					0x21e1cde6U, 0xc33707d6U, 0xf4d50d87U, 0x455a14edU, 0xa9e3e905U, 0xfcefa3f8U, 0x676f02d9U, 0x8d2a4c8aU,
					0xfffa3942U, 0x8771f681U, 0x6d9d6122U, 0xfde5380cU, 0xa4beea44U, 0x4bdecfa9U, 0xf6bb4b60U, 0xbebfbc70U,
					0x289b7ec6U, 0xeaa127faU, 0xd4ef3085U, 0x04881d05U, 0xd9d4d039U, 0xe6db99e5U, 0x1fa27cf8U, 0xc4ac5665U,
					0xf4292244U, 0x432aff97U, 0xab9423a7U, 0xfc93a039U, 0x655b59c3U, 0x8f0ccc92U, 0xffeff47dU, 0x85845dd1U,
					0x6fa87e4fU, 0xfe2ce6e0U, 0xa3014314U, 0x4e0811a1U, 0xf7537e82U, 0xbd3af235U, 0x2ad7d2bbU, 0xeb86d391U
				};
				static const int S[64] = {
					7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
					5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
					4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
					6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
				};
				EIF_NATURAL_32 *H = (EIF_NATURAL_32 *) $a_state;
				const unsigned char *p = (const unsigned char *) $a_data;
				EIF_INTEGER n = $a_blocks;
				EIF_NATURAL_32 M[16];
				EIF_NATURAL_32 a, b, c, d, f, t;
				int i, g;
				for (; n > 0; n--, p += 64) {
					for (i = 0; i < 16; i++) {
						M[i] = (EIF_NATURAL_32) p[4 * i] | ((EIF_NATURAL_32) p[4 * i + 1] << 8)
							| ((EIF_NATURAL_32) p[4 * i + 2] << 16) | ((EIF_NATURAL_32) p[4 * i + 3] << 24);
					}
					a = H[0]; b = H[1]; c = H[2]; d = H[3];
					for (i = 0; i < 64; i++) {
						if (i < 16) {
							f = (b & c) | (~b & d); g = i;
						} else if (i < 32) {
							f = (d & b) | (~d & c); g = (5 * i + 1) & 15;
						} else if (i < 48) {
							f = b ^ c ^ d; g = (3 * i + 5) & 15;
						} else {
							f = c ^ (b | ~d); g = (7 * i) & 15;
						}
						t = d; d = c; c = b;
						f = a + f + K[i] + M[g];
						b = b + ((f << S[i]) | (f >> (32 - S[i])));
						a = t;
					}
					H[0] += a; H[1] += b; H[2] += c; H[3] += d;
				}
			]"
		end

note
	copyright: "Copyright (c) 2024-2026, Larry Rix"
	license: "MIT License"

end
