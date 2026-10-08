note
	description: "[
		Streaming SHA-256 (FIPS 180-4). 64-byte blocks, 32-byte digest.
		See SIMPLE_HASH_STATE for the feeding protocol.
	]"
	author: "Larry Rix"
	date: "$Date$"
	revision: "$Revision$"
	EIS: "name=FIPS 180-4", "src=https://csrc.nist.gov/publications/detail/fips/180/4/final", "protocol=URI", "tag=specification"

class
	SIMPLE_SHA256_STATE

inherit
	SIMPLE_HASH_STATE

create
	make

feature -- Measurement

	block_size: INTEGER = 64
			-- <Precursor>

	digest_size: INTEGER = 32
			-- <Precursor>

feature {NONE} -- Implementation

	chaining_size: INTEGER = 32
			-- <Precursor>

	length_field_size: INTEGER = 8
			-- <Precursor>

	is_length_big_endian: BOOLEAN = True
			-- <Precursor>

	load_initial_chaining
			-- <Precursor>
		do
			chaining.put_natural_32 (0x6a09e667, 0)
			chaining.put_natural_32 (0xbb67ae85, 4)
			chaining.put_natural_32 (0x3c6ef372, 8)
			chaining.put_natural_32 (0xa54ff53a, 12)
			chaining.put_natural_32 (0x510e527f, 16)
			chaining.put_natural_32 (0x9b05688c, 20)
			chaining.put_natural_32 (0x1f83d9ab, 24)
			chaining.put_natural_32 (0x5be0cd19, 28)
		end

	chaining_digest: ARRAY [NATURAL_8]
			-- <Precursor>
		local
			i: INTEGER
			l_word: NATURAL_32
		do
			create Result.make_filled (0, 1, digest_size)
			from i := 0 until i = 8 loop
				l_word := chaining.read_natural_32 (i * 4)
				Result [i * 4 + 1] := (l_word |>> 24).to_natural_8
				Result [i * 4 + 2] := (l_word |>> 16).to_natural_8
				Result [i * 4 + 3] := (l_word |>> 8).to_natural_8
				Result [i * 4 + 4] := l_word.to_natural_8
				i := i + 1
			variant
				8 - i
			end
		end

	compress_blocks (a_state, a_data: POINTER; a_blocks: INTEGER)
			-- <Precursor>
		external
			"C blocking inline"
		alias
			"[
				static const EIF_NATURAL_32 K[64] = {
					0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
					0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
					0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
					0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
					0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
					0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
					0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
					0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
				};
				EIF_NATURAL_32 *H = (EIF_NATURAL_32 *) $a_state;
				const unsigned char *p = (const unsigned char *) $a_data;
				EIF_INTEGER n = $a_blocks;
				EIF_NATURAL_32 W[64];
				EIF_NATURAL_32 a, b, c, d, e, f, g, h, t1, t2;
				int i;
				#define SH256_ROTR(x, s) (((x) >> (s)) | ((x) << (32 - (s))))
				for (; n > 0; n--, p += 64) {
					for (i = 0; i < 16; i++) {
						W[i] = ((EIF_NATURAL_32) p[4 * i] << 24) | ((EIF_NATURAL_32) p[4 * i + 1] << 16)
							| ((EIF_NATURAL_32) p[4 * i + 2] << 8) | (EIF_NATURAL_32) p[4 * i + 3];
					}
					for (i = 16; i < 64; i++) {
						W[i] = W[i - 16]
							+ (SH256_ROTR(W[i - 15], 7) ^ SH256_ROTR(W[i - 15], 18) ^ (W[i - 15] >> 3))
							+ W[i - 7]
							+ (SH256_ROTR(W[i - 2], 17) ^ SH256_ROTR(W[i - 2], 19) ^ (W[i - 2] >> 10));
					}
					a = H[0]; b = H[1]; c = H[2]; d = H[3]; e = H[4]; f = H[5]; g = H[6]; h = H[7];
					for (i = 0; i < 64; i++) {
						t1 = h + (SH256_ROTR(e, 6) ^ SH256_ROTR(e, 11) ^ SH256_ROTR(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + W[i];
						t2 = (SH256_ROTR(a, 2) ^ SH256_ROTR(a, 13) ^ SH256_ROTR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
						h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
					}
					H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
				}
				#undef SH256_ROTR
			]"
		end

note
	copyright: "Copyright (c) 2024-2026, Larry Rix"
	license: "MIT License"

end
