note
	description: "[
		Streaming SHA-1 (FIPS 180-4). 64-byte blocks, 20-byte digest.
		SHA-1 is broken for collision resistance; use it only where a protocol
		requires it (WebSocket handshake, git object names).
		See SIMPLE_HASH_STATE for the feeding protocol.
	]"
	author: "Larry Rix"
	date: "$Date$"
	revision: "$Revision$"
	EIS: "name=FIPS 180-4", "src=https://csrc.nist.gov/publications/detail/fips/180/4/final", "protocol=URI", "tag=specification"

class
	SIMPLE_SHA1_STATE

inherit
	SIMPLE_HASH_STATE

create
	make

feature -- Measurement

	block_size: INTEGER = 64
			-- <Precursor>

	digest_size: INTEGER = 20
			-- <Precursor>

feature {NONE} -- Implementation

	chaining_size: INTEGER = 20
			-- <Precursor>

	length_field_size: INTEGER = 8
			-- <Precursor>

	is_length_big_endian: BOOLEAN = True
			-- <Precursor>

	load_initial_chaining
			-- <Precursor>
		do
			chaining.put_natural_32 (0x67452301, 0)
			chaining.put_natural_32 (0xEFCDAB89, 4)
			chaining.put_natural_32 (0x98BADCFE, 8)
			chaining.put_natural_32 (0x10325476, 12)
			chaining.put_natural_32 (0xC3D2E1F0, 16)
		end

	chaining_digest: ARRAY [NATURAL_8]
			-- <Precursor>
		local
			i: INTEGER
			l_word: NATURAL_32
		do
			create Result.make_filled (0, 1, digest_size)
			from i := 0 until i = 5 loop
				l_word := chaining.read_natural_32 (i * 4)
				Result [i * 4 + 1] := (l_word |>> 24).to_natural_8
				Result [i * 4 + 2] := (l_word |>> 16).to_natural_8
				Result [i * 4 + 3] := (l_word |>> 8).to_natural_8
				Result [i * 4 + 4] := l_word.to_natural_8
				i := i + 1
			variant
				5 - i
			end
		end

	compress_blocks (a_state, a_data: POINTER; a_blocks: INTEGER)
			-- <Precursor>
		external
			"C blocking inline"
		alias
			"[
				EIF_NATURAL_32 *H = (EIF_NATURAL_32 *) $a_state;
				const unsigned char *p = (const unsigned char *) $a_data;
				EIF_INTEGER n = $a_blocks;
				EIF_NATURAL_32 W[80];
				EIF_NATURAL_32 a, b, c, d, e, f, k, t;
				int i;
				#define SH1_ROTL(x, s) (((x) << (s)) | ((x) >> (32 - (s))))
				for (; n > 0; n--, p += 64) {
					for (i = 0; i < 16; i++) {
						W[i] = ((EIF_NATURAL_32) p[4 * i] << 24) | ((EIF_NATURAL_32) p[4 * i + 1] << 16)
							| ((EIF_NATURAL_32) p[4 * i + 2] << 8) | (EIF_NATURAL_32) p[4 * i + 3];
					}
					for (i = 16; i < 80; i++) {
						t = W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16];
						W[i] = SH1_ROTL(t, 1);
					}
					a = H[0]; b = H[1]; c = H[2]; d = H[3]; e = H[4];
					for (i = 0; i < 80; i++) {
						if (i < 20) {
							f = (b & c) | (~b & d); k = 0x5A827999U;
						} else if (i < 40) {
							f = b ^ c ^ d; k = 0x6ED9EBA1U;
						} else if (i < 60) {
							f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDCU;
						} else {
							f = b ^ c ^ d; k = 0xCA62C1D6U;
						}
						t = SH1_ROTL(a, 5) + f + e + k + W[i];
						e = d; d = c; c = SH1_ROTL(b, 30); b = a; a = t;
					}
					H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e;
				}
				#undef SH1_ROTL
			]"
		end

note
	copyright: "Copyright (c) 2024-2026, Larry Rix"
	license: "MIT License"

end
