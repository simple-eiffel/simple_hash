note
	description: "[
		Streaming, vector and file tests for simple_hash 1.1.0 (D15 + Unicode paths).
		Every expected digest was computed by Python hashlib (an independent
		implementation); the FIPS/RFC vectors were cross-checked with GNU
		coreutils sha1sum, sha256sum, sha512sum and md5sum.
	]"
	testing: "covers"

class
	STREAMING_TESTS

inherit
	TEST_SET_BASE

feature -- Test: standard vectors (FIPS 180-4 / RFC 1321 messages)


	test_vectors_sha1
			-- "", "abc", the 448-bit and 896-bit messages and one million 'a' through `sha1'.
		note
			testing: "covers/{SIMPLE_HASH}.sha1"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			assert_strings_equal ("sha1 empty", "da39a3ee5e6b4b0d3255bfef95601890afd80709", hasher.sha1 (""))
			assert_strings_equal ("sha1 abc", "a9993e364706816aba3e25717850c26c9cd0d89d", hasher.sha1 ("abc"))
			assert_strings_equal ("sha1 448", "84983e441c3bd26ebaae4aa1f95129e5e54670f1", hasher.sha1 ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
			assert_strings_equal ("sha1 896", "a49b2446a02c645bf419f995b67091253a04a259", hasher.sha1 ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"))
			assert_strings_equal ("sha1 million_a", "34aa973cd4c4daa4f61eeb2bdbad27316534016f", hasher.sha1 (million_a))
		end

	test_vectors_sha256
			-- "", "abc", the 448-bit and 896-bit messages and one million 'a' through `sha256'.
		note
			testing: "covers/{SIMPLE_HASH}.sha256"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			assert_strings_equal ("sha256 empty", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hasher.sha256 (""))
			assert_strings_equal ("sha256 abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", hasher.sha256 ("abc"))
			assert_strings_equal ("sha256 448", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", hasher.sha256 ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
			assert_strings_equal ("sha256 896", "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1", hasher.sha256 ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"))
			assert_strings_equal ("sha256 million_a", "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", hasher.sha256 (million_a))
		end

	test_vectors_sha512
			-- "", "abc", the 448-bit and 896-bit messages and one million 'a' through `sha512'.
		note
			testing: "covers/{SIMPLE_HASH}.sha512"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			assert_strings_equal ("sha512 empty", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", hasher.sha512 (""))
			assert_strings_equal ("sha512 abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", hasher.sha512 ("abc"))
			assert_strings_equal ("sha512 448", "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445", hasher.sha512 ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
			assert_strings_equal ("sha512 896", "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909", hasher.sha512 ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"))
			assert_strings_equal ("sha512 million_a", "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b", hasher.sha512 (million_a))
		end

	test_vectors_md5
			-- "", "abc", the 448-bit and 896-bit messages and one million 'a' through `md5'.
		note
			testing: "covers/{SIMPLE_HASH}.md5"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			assert_strings_equal ("md5 empty", "d41d8cd98f00b204e9800998ecf8427e", hasher.md5 (""))
			assert_strings_equal ("md5 abc", "900150983cd24fb0d6963f7d28e17f72", hasher.md5 ("abc"))
			assert_strings_equal ("md5 448", "8215ef0796a20bcaaae116d3876c664a", hasher.md5 ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
			assert_strings_equal ("md5 896", "03dd8807a93175fb062dfb55dc7d359c", hasher.md5 ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"))
			assert_strings_equal ("md5 million_a", "7707d6ae4e027c70eea2a935c2296f21", hasher.md5 (million_a))
		end

	test_md5_rfc1321_suite
			-- The RFC 1321 appendix A.5 test suite.
		note
			testing: "covers/{SIMPLE_HASH}.md5"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			assert_strings_equal ("md5 ", "d41d8cd98f00b204e9800998ecf8427e", hasher.md5 (""))
			assert_strings_equal ("md5 a", "0cc175b9c0f1b6a831c399e269772661", hasher.md5 ("a"))
			assert_strings_equal ("md5 abc", "900150983cd24fb0d6963f7d28e17f72", hasher.md5 ("abc"))
			assert_strings_equal ("md5 message digest", "f96b697d7cb7938d525a2f31aaf161d0", hasher.md5 ("message digest"))
			assert_strings_equal ("md5 abcdefghijklmnopqrst", "c3fcd3d76192e4007dfb496cca67e13b", hasher.md5 ("abcdefghijklmnopqrstuvwxyz"))
			assert_strings_equal ("md5 ABCDEFGHIJKLMNOPQRST", "d174ab98d277d9f5a5611c2c9f419d9f", hasher.md5 ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"))
			assert_strings_equal ("md5 12345678901234567890", "57edf4a22be3c955ac49da2e2107b67a", hasher.md5 ("12345678901234567890123456789012345678901234567890123456789012345678901234567890"))
		end

feature -- Test: padding boundaries


	test_boundary_lengths_sha1
			-- Messages of 'a' at every length where padding spills into a second block.
		note
			testing: "covers/{SIMPLE_HASH}.sha1"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			assert_strings_equal ("sha1 len 55", "c1c8bbdc22796e28c0e15163d20899b65621d65a", hasher.sha1 (create {STRING}.make_filled ('a', 55)))
			assert_strings_equal ("sha1 len 56", "c2db330f6083854c99d4b5bfb6e8f29f201be699", hasher.sha1 (create {STRING}.make_filled ('a', 56)))
			assert_strings_equal ("sha1 len 57", "f08f24908d682555111be7ff6f004e78283d989a", hasher.sha1 (create {STRING}.make_filled ('a', 57)))
			assert_strings_equal ("sha1 len 63", "03f09f5b158a7a8cdad920bddc29b81c18a551f5", hasher.sha1 (create {STRING}.make_filled ('a', 63)))
			assert_strings_equal ("sha1 len 64", "0098ba824b5c16427bd7a1122a5a442a25ec644d", hasher.sha1 (create {STRING}.make_filled ('a', 64)))
			assert_strings_equal ("sha1 len 65", "11655326c708d70319be2610e8a57d9a5b959d3b", hasher.sha1 (create {STRING}.make_filled ('a', 65)))
			assert_strings_equal ("sha1 len 111", "ac877859d427d9192054eea8feb3b8a403ef83a5", hasher.sha1 (create {STRING}.make_filled ('a', 111)))
			assert_strings_equal ("sha1 len 112", "689993727ba37386bb032495e9dbdfb4dd1ba744", hasher.sha1 (create {STRING}.make_filled ('a', 112)))
			assert_strings_equal ("sha1 len 113", "3bcfff44cf3237b9b63c661a530077f794872efc", hasher.sha1 (create {STRING}.make_filled ('a', 113)))
			assert_strings_equal ("sha1 len 127", "89d95fa32ed44a7c610b7ee38517ddf57e0bb975", hasher.sha1 (create {STRING}.make_filled ('a', 127)))
			assert_strings_equal ("sha1 len 128", "ad5b3fdbcb526778c2839d2f151ea753995e26a0", hasher.sha1 (create {STRING}.make_filled ('a', 128)))
			assert_strings_equal ("sha1 len 129", "d96debf1bdcbc896e6c134ea76e8141f40d78536", hasher.sha1 (create {STRING}.make_filled ('a', 129)))
		end

	test_boundary_lengths_sha256
			-- Messages of 'a' at every length where padding spills into a second block.
		note
			testing: "covers/{SIMPLE_HASH}.sha256"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			assert_strings_equal ("sha256 len 55", "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318", hasher.sha256 (create {STRING}.make_filled ('a', 55)))
			assert_strings_equal ("sha256 len 56", "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a", hasher.sha256 (create {STRING}.make_filled ('a', 56)))
			assert_strings_equal ("sha256 len 57", "f13b2d724659eb3bf47f2dd6af1accc87b81f09f59f2b75e5c0bed6589dfe8c6", hasher.sha256 (create {STRING}.make_filled ('a', 57)))
			assert_strings_equal ("sha256 len 63", "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34", hasher.sha256 (create {STRING}.make_filled ('a', 63)))
			assert_strings_equal ("sha256 len 64", "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb", hasher.sha256 (create {STRING}.make_filled ('a', 64)))
			assert_strings_equal ("sha256 len 65", "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0", hasher.sha256 (create {STRING}.make_filled ('a', 65)))
			assert_strings_equal ("sha256 len 111", "6374f73208854473827f6f6a3f43b1f53eaa3b82c21c1a6d69a2110b2a79baad", hasher.sha256 (create {STRING}.make_filled ('a', 111)))
			assert_strings_equal ("sha256 len 112", "f54353008a2553262ecdc4a34749563ba0950e8b0fc8652780b0a614b99683c1", hasher.sha256 (create {STRING}.make_filled ('a', 112)))
			assert_strings_equal ("sha256 len 113", "ba02731ae695aae5cd49b49d84330b63995733eb22102aca755f0179b1e0e20f", hasher.sha256 (create {STRING}.make_filled ('a', 113)))
			assert_strings_equal ("sha256 len 127", "c57e9278af78fa3cab38667bef4ce29d783787a2f731d4e12200270f0c32320a", hasher.sha256 (create {STRING}.make_filled ('a', 127)))
			assert_strings_equal ("sha256 len 128", "6836cf13bac400e9105071cd6af47084dfacad4e5e302c94bfed24e013afb73e", hasher.sha256 (create {STRING}.make_filled ('a', 128)))
			assert_strings_equal ("sha256 len 129", "c12cb024a2e5551cca0e08fce8f1c5e314555cc3fef6329ee994a3db752166ae", hasher.sha256 (create {STRING}.make_filled ('a', 129)))
		end

	test_boundary_lengths_sha512
			-- Messages of 'a' at every length where padding spills into a second block.
		note
			testing: "covers/{SIMPLE_HASH}.sha512"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			assert_strings_equal ("sha512 len 55", "b0220c772cbf6c1822e2cb38a437d0e1d58772417a4bbb21c961364f8b6143e05aa6316dca8d1d7b19e16448419076395f6086cb55101fbd6d5497b148e1745f", hasher.sha512 (create {STRING}.make_filled ('a', 55)))
			assert_strings_equal ("sha512 len 56", "962b64aae357d2a4fee3ded8b539bdc9d325081822b0bfc55583133aab44f18bafe11d72a7ae16c79ce2ba620ae2242d5144809161945f1367f41b3972e26e04", hasher.sha512 (create {STRING}.make_filled ('a', 56)))
			assert_strings_equal ("sha512 len 57", "d3115798e872fc1ca6b276368e8ea0926daec6ab1f8f08297e4348ff5f5fe4c6e5205413271babafd4929b070754bc5800e5db44790666ec4e2f6ac52a17e163", hasher.sha512 (create {STRING}.make_filled ('a', 57)))
			assert_strings_equal ("sha512 len 63", "c1b0f5c6d3b03dfe4a2602e67242f54e344090b66e01100a469b129f583f016c7e27dddeaa438393dcc7ec54b0b57c9ba7af007f9b56db5f6fb677d972a31362", hasher.sha512 (create {STRING}.make_filled ('a', 63)))
			assert_strings_equal ("sha512 len 64", "01d35c10c6c38c2dcf48f7eebb3235fb5ad74a65ec4cd016e2354c637a8fb49b695ef3c1d6f7ae4cd74d78cc9c9bcac9d4f23a73019998a7f73038a5c9b2dbde", hasher.sha512 (create {STRING}.make_filled ('a', 64)))
			assert_strings_equal ("sha512 len 65", "b83086cd8494e55708ad7ecd82dfb4bca1bda61ecbb7caf0c68967902e709345e5d8305eb7ac0d588afc6cbb75161aa9c8c7e0ea986bd833dafe5e1ccd37345a", hasher.sha512 (create {STRING}.make_filled ('a', 65)))
			assert_strings_equal ("sha512 len 111", "fa9121c7b32b9e01733d034cfc78cbf67f926c7ed83e82200ef86818196921760b4beff48404df811b953828274461673c68d04e297b0eb7b2b4d60fc6b566a2", hasher.sha512 (create {STRING}.make_filled ('a', 111)))
			assert_strings_equal ("sha512 len 112", "c01d080efd492776a1c43bd23dd99d0a2e626d481e16782e75d54c2503b5dc32bd05f0f1ba33e568b88fd2d970929b719ecbb152f58f130a407c8830604b70ca", hasher.sha512 (create {STRING}.make_filled ('a', 112)))
			assert_strings_equal ("sha512 len 113", "55ddd8ac210a6e18ba1ee055af84c966e0dbff091c43580ae1be703bdb85da31acf6948cf5bd90c55a20e5450f22fb89bd8d0085e39f85a86cc46abbca75e24d", hasher.sha512 (create {STRING}.make_filled ('a', 113)))
			assert_strings_equal ("sha512 len 127", "828613968b501dc00a97e08c73b118aa8876c26b8aac93df128502ab360f91bab50a51e088769a5c1eff4782ace147dce3642554199876374291f5d921629502", hasher.sha512 (create {STRING}.make_filled ('a', 127)))
			assert_strings_equal ("sha512 len 128", "b73d1929aa615934e61a871596b3f3b33359f42b8175602e89f7e06e5f658a243667807ed300314b95cacdd579f3e33abdfbe351909519a846d465c59582f321", hasher.sha512 (create {STRING}.make_filled ('a', 128)))
			assert_strings_equal ("sha512 len 129", "4f681e0bd53cda4b5a2041cc8a06f2eabde44fb16c951fbd5b87702f07aeab611565b19c47fde30587177ebb852e3971bbd8d3fd30da18d71037dfbd98420429", hasher.sha512 (create {STRING}.make_filled ('a', 129)))
		end

	test_boundary_lengths_md5
			-- Messages of 'a' at every length where padding spills into a second block.
		note
			testing: "covers/{SIMPLE_HASH}.md5"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			assert_strings_equal ("md5 len 55", "ef1772b6dff9a122358552954ad0df65", hasher.md5 (create {STRING}.make_filled ('a', 55)))
			assert_strings_equal ("md5 len 56", "3b0c8ac703f828b04c6c197006d17218", hasher.md5 (create {STRING}.make_filled ('a', 56)))
			assert_strings_equal ("md5 len 57", "652b906d60af96844ebd21b674f35e93", hasher.md5 (create {STRING}.make_filled ('a', 57)))
			assert_strings_equal ("md5 len 63", "b06521f39153d618550606be297466d5", hasher.md5 (create {STRING}.make_filled ('a', 63)))
			assert_strings_equal ("md5 len 64", "014842d480b571495a4a0363793f7367", hasher.md5 (create {STRING}.make_filled ('a', 64)))
			assert_strings_equal ("md5 len 65", "c743a45e0d2e6a95cb859adae0248435", hasher.md5 (create {STRING}.make_filled ('a', 65)))
			assert_strings_equal ("md5 len 111", "089f243d1e831c5879aa375ee364a06e", hasher.md5 (create {STRING}.make_filled ('a', 111)))
			assert_strings_equal ("md5 len 112", "9146ef3527c7cfcc66dc615c3986e391", hasher.md5 (create {STRING}.make_filled ('a', 112)))
			assert_strings_equal ("md5 len 113", "d727cfdfc9ed0347e6917a68b982f7bc", hasher.md5 (create {STRING}.make_filled ('a', 113)))
			assert_strings_equal ("md5 len 127", "020406e1d05cdc2aa287641f7ae2cc39", hasher.md5 (create {STRING}.make_filled ('a', 127)))
			assert_strings_equal ("md5 len 128", "e510683b3f5ffe4093d021808bc6ff70", hasher.md5 (create {STRING}.make_filled ('a', 128)))
			assert_strings_equal ("md5 len 129", "b325dc1c6f5e7a2b7cf465b9feab7948", hasher.md5 (create {STRING}.make_filled ('a', 129)))
		end

feature -- Test: incremental feeding


	test_streaming_pieces_sha1
			-- 5000 pattern bytes fed in ragged pieces (1, 63, 64, 65, 127, 128, 129, ...)
			-- through every update route, then the state reset and reused.
		note
			testing: "covers/{SIMPLE_SHA1_STATE}.update", "covers/{SIMPLE_SHA1_STATE}.update_bytes", "covers/{SIMPLE_SHA1_STATE}.update_from_managed", "covers/{SIMPLE_SHA1_STATE}.reset"
		local
			l_state: SIMPLE_SHA1_STATE
		do
			create l_state.make
			feed_in_pieces (l_state, pattern_string (5000))
			assert_strings_equal ("sha1 pieces", "d2709e191de54e8664f00eb5bc8927b5250af64f", l_state.digest_hex)
			assert ("sha1 byte_count", l_state.byte_count = 5000)
			l_state.reset
			l_state.update ("abc")
			l_state.finish
			assert_strings_equal ("sha1 after reset", "a9993e364706816aba3e25717850c26c9cd0d89d", l_state.digest_hex)
			l_state.reset
			l_state.update (create {IMMUTABLE_STRING_8}.make_from_string ("abc"))
			l_state.finish
			assert_strings_equal ("sha1 immutable string", "a9993e364706816aba3e25717850c26c9cd0d89d", l_state.digest_hex)
		end

	test_streaming_pieces_sha256
			-- 5000 pattern bytes fed in ragged pieces (1, 63, 64, 65, 127, 128, 129, ...)
			-- through every update route, then the state reset and reused.
		note
			testing: "covers/{SIMPLE_SHA256_STATE}.update", "covers/{SIMPLE_SHA256_STATE}.update_bytes", "covers/{SIMPLE_SHA256_STATE}.update_from_managed", "covers/{SIMPLE_SHA256_STATE}.reset"
		local
			l_state: SIMPLE_SHA256_STATE
		do
			create l_state.make
			feed_in_pieces (l_state, pattern_string (5000))
			assert_strings_equal ("sha256 pieces", "0ee0b811d80affcc3ebbcbbcf05ab2043e67c5787fe7e5a56accb282588aff8a", l_state.digest_hex)
			assert ("sha256 byte_count", l_state.byte_count = 5000)
			l_state.reset
			l_state.update ("abc")
			l_state.finish
			assert_strings_equal ("sha256 after reset", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", l_state.digest_hex)
			l_state.reset
			l_state.update (create {IMMUTABLE_STRING_8}.make_from_string ("abc"))
			l_state.finish
			assert_strings_equal ("sha256 immutable string", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", l_state.digest_hex)
		end

	test_streaming_pieces_sha512
			-- 5000 pattern bytes fed in ragged pieces (1, 63, 64, 65, 127, 128, 129, ...)
			-- through every update route, then the state reset and reused.
		note
			testing: "covers/{SIMPLE_SHA512_STATE}.update", "covers/{SIMPLE_SHA512_STATE}.update_bytes", "covers/{SIMPLE_SHA512_STATE}.update_from_managed", "covers/{SIMPLE_SHA512_STATE}.reset"
		local
			l_state: SIMPLE_SHA512_STATE
		do
			create l_state.make
			feed_in_pieces (l_state, pattern_string (5000))
			assert_strings_equal ("sha512 pieces", "56d9151800a9a5918ed8a7627a251a573d6affa7ec0c9396ddd762a90501e644f26a315f4ef3e630535ee8cfdd69b3ce43b47735d66415a67551b4fd4f0ba16c", l_state.digest_hex)
			assert ("sha512 byte_count", l_state.byte_count = 5000)
			l_state.reset
			l_state.update ("abc")
			l_state.finish
			assert_strings_equal ("sha512 after reset", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", l_state.digest_hex)
			l_state.reset
			l_state.update (create {IMMUTABLE_STRING_8}.make_from_string ("abc"))
			l_state.finish
			assert_strings_equal ("sha512 immutable string", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", l_state.digest_hex)
		end

	test_streaming_pieces_md5
			-- 5000 pattern bytes fed in ragged pieces (1, 63, 64, 65, 127, 128, 129, ...)
			-- through every update route, then the state reset and reused.
		note
			testing: "covers/{SIMPLE_MD5_STATE}.update", "covers/{SIMPLE_MD5_STATE}.update_bytes", "covers/{SIMPLE_MD5_STATE}.update_from_managed", "covers/{SIMPLE_MD5_STATE}.reset"
		local
			l_state: SIMPLE_MD5_STATE
		do
			create l_state.make
			feed_in_pieces (l_state, pattern_string (5000))
			assert_strings_equal ("md5 pieces", "213d56f64b0348237b873d78c3fb398f", l_state.digest_hex)
			assert ("md5 byte_count", l_state.byte_count = 5000)
			l_state.reset
			l_state.update ("abc")
			l_state.finish
			assert_strings_equal ("md5 after reset", "900150983cd24fb0d6963f7d28e17f72", l_state.digest_hex)
			l_state.reset
			l_state.update (create {IMMUTABLE_STRING_8}.make_from_string ("abc"))
			l_state.finish
			assert_strings_equal ("md5 immutable string", "900150983cd24fb0d6963f7d28e17f72", l_state.digest_hex)
		end

feature -- Test: file hashing


	test_multichunk_file_sha1
			-- A 798777-byte file (3 x File_chunk_size + 12345: not a multiple of
			-- the block or the chunk size): file digest = in-memory digest = hashlib.
		note
			testing: "covers/{SIMPLE_HASH}.sha1_file", "covers/{SIMPLE_HASH}.sha1"
		local
			hasher: SIMPLE_HASH
			l_content: STRING
			l_path: STRING
		do
			create hasher.make
			assert ("size not chunk multiple", 798777 \\ hasher.File_chunk_size /= 0)
			l_path := "test_hash_multichunk_sha1.bin"
			l_content := pattern_string (798777)
			write_file (l_path, l_content)
			assert_strings_equal ("sha1 in memory", "84f7d15c7ff15ea20b79c4c65593854b1472b896", hasher.sha1 (l_content))
			if attached hasher.sha1_file (l_path) as al_file_hex then
				assert_strings_equal ("sha1 file", "84f7d15c7ff15ea20b79c4c65593854b1472b896", al_file_hex)
			else
				assert ("sha1 file hash not void", False)
			end
			delete_file (l_path)
		end

	test_multichunk_file_sha256
			-- A 798777-byte file (3 x File_chunk_size + 12345: not a multiple of
			-- the block or the chunk size): file digest = in-memory digest = hashlib.
		note
			testing: "covers/{SIMPLE_HASH}.sha256_file", "covers/{SIMPLE_HASH}.sha256"
		local
			hasher: SIMPLE_HASH
			l_content: STRING
			l_path: STRING
		do
			create hasher.make
			assert ("size not chunk multiple", 798777 \\ hasher.File_chunk_size /= 0)
			l_path := "test_hash_multichunk_sha256.bin"
			l_content := pattern_string (798777)
			write_file (l_path, l_content)
			assert_strings_equal ("sha256 in memory", "6d0e079746fc0c1faf478da9e9905c0cd828c4f3822840d39bf24795f17a8050", hasher.sha256 (l_content))
			if attached hasher.sha256_file (l_path) as al_file_hex then
				assert_strings_equal ("sha256 file", "6d0e079746fc0c1faf478da9e9905c0cd828c4f3822840d39bf24795f17a8050", al_file_hex)
			else
				assert ("sha256 file hash not void", False)
			end
			delete_file (l_path)
		end

	test_multichunk_file_sha512
			-- A 798777-byte file (3 x File_chunk_size + 12345: not a multiple of
			-- the block or the chunk size): file digest = in-memory digest = hashlib.
		note
			testing: "covers/{SIMPLE_HASH}.sha512_file", "covers/{SIMPLE_HASH}.sha512"
		local
			hasher: SIMPLE_HASH
			l_content: STRING
			l_path: STRING
		do
			create hasher.make
			assert ("size not chunk multiple", 798777 \\ hasher.File_chunk_size /= 0)
			l_path := "test_hash_multichunk_sha512.bin"
			l_content := pattern_string (798777)
			write_file (l_path, l_content)
			assert_strings_equal ("sha512 in memory", "d83d7e19a89db57df554e14a455f3ef6a2671b95fc4c0a1b14cc5d467dcd9626ff25f1c69d0eeb66352a1919759e58a30aeccd645e1b81fd230403eb04883561", hasher.sha512 (l_content))
			if attached hasher.sha512_file (l_path) as al_file_hex then
				assert_strings_equal ("sha512 file", "d83d7e19a89db57df554e14a455f3ef6a2671b95fc4c0a1b14cc5d467dcd9626ff25f1c69d0eeb66352a1919759e58a30aeccd645e1b81fd230403eb04883561", al_file_hex)
			else
				assert ("sha512 file hash not void", False)
			end
			delete_file (l_path)
		end

	test_multichunk_file_md5
			-- A 798777-byte file (3 x File_chunk_size + 12345: not a multiple of
			-- the block or the chunk size): file digest = in-memory digest = hashlib.
		note
			testing: "covers/{SIMPLE_HASH}.md5_file", "covers/{SIMPLE_HASH}.md5"
		local
			hasher: SIMPLE_HASH
			l_content: STRING
			l_path: STRING
		do
			create hasher.make
			assert ("size not chunk multiple", 798777 \\ hasher.File_chunk_size /= 0)
			l_path := "test_hash_multichunk_md5.bin"
			l_content := pattern_string (798777)
			write_file (l_path, l_content)
			assert_strings_equal ("md5 in memory", "4c783312a0659300a287090b80b8f587", hasher.md5 (l_content))
			if attached hasher.md5_file (l_path) as al_file_hex then
				assert_strings_equal ("md5 file", "4c783312a0659300a287090b80b8f587", al_file_hex)
			else
				assert ("md5 file hash not void", False)
			end
			delete_file (l_path)
		end

	test_unicode_file_name
			-- A file whose name holds Hebrew and Greek letters, reached through a
			-- STRING_32 name and through a PATH, by every algorithm.
		note
			testing: "covers/{SIMPLE_HASH}.sha256_file", "covers/{SIMPLE_HASH}.sha256_path"
		local
			hasher: SIMPLE_HASH
			l_name: STRING_32
			l_file: RAW_FILE
		do
			create hasher.make
			l_name := unicode_name
			assert ("name is not 8-bit", not l_name.is_valid_as_string_8)
			create l_file.make_with_name (l_name)
			l_file.open_write
			l_file.put_string ("Hello, World!")
			l_file.close
			assert ("unicode file exists", l_file.exists)
			assert_strings_equal ("sha256", "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f", attached_or_empty (hasher.sha256_file (l_name)))
			assert_strings_equal ("sha512", "374d794a95cdcfd8b35993185fef9ba368f160d8daf432d08ba9f1ed1e5abe6cc69291e0fa2fe0006a52570ef18c19def4e617c33ce52ef0a6e5fbe318cb0387", attached_or_empty (hasher.sha512_file (l_name)))
			assert_strings_equal ("sha1", "0a0a9f2a6772942557ab5355d76af442f8f65e01", attached_or_empty (hasher.sha1_file (l_name)))
			assert_strings_equal ("md5", "65a8e27d8879283831b664bd8b7f0ad4", attached_or_empty (hasher.md5_file (l_name)))
			assert_strings_equal ("sha256 path", "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f", attached_or_empty (hasher.sha256_path (create {PATH}.make_from_string (l_name))))
			assert_strings_equal ("sha512 path", "374d794a95cdcfd8b35993185fef9ba368f160d8daf432d08ba9f1ed1e5abe6cc69291e0fa2fe0006a52570ef18c19def4e617c33ce52ef0a6e5fbe318cb0387", attached_or_empty (hasher.sha512_path (create {PATH}.make_from_string (l_name))))
			assert_strings_equal ("sha1 path", "0a0a9f2a6772942557ab5355d76af442f8f65e01", attached_or_empty (hasher.sha1_path (create {PATH}.make_from_string (l_name))))
			assert_strings_equal ("md5 path", "65a8e27d8879283831b664bd8b7f0ad4", attached_or_empty (hasher.md5_path (create {PATH}.make_from_string (l_name))))
			l_file.delete
			assert ("unicode file removed", not l_file.exists)
		end

	test_empty_file
			-- A zero-byte file hashes to the empty-message digests.
		note
			testing: "covers/{SIMPLE_HASH}.sha256_file"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			write_file ("test_hash_empty.bin", "")
			assert_strings_equal ("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", attached_or_empty (hasher.sha256_file ("test_hash_empty.bin")))
			assert_strings_equal ("sha512", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", attached_or_empty (hasher.sha512_file ("test_hash_empty.bin")))
			assert_strings_equal ("sha1", "da39a3ee5e6b4b0d3255bfef95601890afd80709", attached_or_empty (hasher.sha1_file ("test_hash_empty.bin")))
			assert_strings_equal ("md5", "d41d8cd98f00b204e9800998ecf8427e", attached_or_empty (hasher.md5_file ("test_hash_empty.bin")))
			delete_file ("test_hash_empty.bin")
		end

	test_directory_is_void
			-- A directory is not a readable file: Void, no exception.
		note
			testing: "covers/{SIMPLE_HASH}.sha256_file"
		local
			hasher: SIMPLE_HASH
			l_dir: DIRECTORY
		do
			create hasher.make
			create l_dir.make_with_name ("test_hash_dir")
			if not l_dir.exists then
				l_dir.create_dir
			end
			assert ("dir sha256 void", hasher.sha256_file ("test_hash_dir") = Void)
			assert ("dir md5 void", hasher.md5_file ("test_hash_dir") = Void)
			l_dir.delete
		end

	test_missing_file_is_void
			-- Every file route answers Void for a missing file.
		note
			testing: "covers/{SIMPLE_HASH}.sha1_file"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			assert ("sha1 void", hasher.sha1_file ("no_such_file_98765.bin") = Void)
			assert ("sha512 void", hasher.sha512_file_bytes ("no_such_file_98765.bin") = Void)
			assert ("path void", hasher.sha256_path (create {PATH}.make_from_string ("no_such_file_98765.bin")) = Void)
		end


feature -- Test: HMAC with a key longer than the block (RFC 4231 cases 6 and 7)

	test_hmac_rfc4231_long_key
			-- RFC 4231 test cases 6 and 7 (131-byte key of 0xaa) for HMAC-SHA256 and HMAC-SHA512.
		note
			testing: "covers/{SIMPLE_HASH}.hmac_sha256", "covers/{SIMPLE_HASH}.hmac_sha512"
		local
			hasher: SIMPLE_HASH
			l_key: STRING
		do
			create hasher.make
			create l_key.make_filled ('%/170/', 131)
			assert_strings_equal ("hmac256 case 6", "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", hasher.hmac_sha256 (l_key, "Test Using Larger Than Block-Size Key - Hash Key First"))
			assert_strings_equal ("hmac512 case 6", "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598", hasher.hmac_sha512 (l_key, "Test Using Larger Than Block-Size Key - Hash Key First"))
			assert_strings_equal ("hmac256 case 7", "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2", hasher.hmac_sha256 (l_key, "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."))
			assert_strings_equal ("hmac512 case 7", "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58", hasher.hmac_sha512 (l_key, "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."))
		end

feature {NONE} -- Helpers

	million_a: STRING
			-- One million 'a'.
		do
			create Result.make_filled ('a', 1_000_000)
		end

	pattern_string (n: INTEGER): STRING
			-- `n' bytes: byte i = ((i * 2654435761) mod 2^32) >> 13, low 8 bits.
		local
			i: INTEGER
			l_x: NATURAL_32
		do
			create Result.make (n)
			from i := 0 until i = n loop
				l_x := (i.to_natural_32 * 2654435761) |>> 13
				Result.append_character ((l_x & 0xFF).to_character_8)
				i := i + 1
			variant
				n - i
			end
		ensure
			sized: Result.count = n
		end

	feed_in_pieces (a_state: SIMPLE_HASH_STATE; a_data: STRING)
			-- Feed `a_data' in ragged pieces, rotating through `update', `update_bytes'
			-- and `update_from_managed', then finish.
		local
			l_sizes: ARRAY [INTEGER]
			l_pos, l_n, l_k, i: INTEGER
			l_piece: STRING
			l_bytes: ARRAY [NATURAL_8]
			l_buffer: MANAGED_POINTER
		do
			l_sizes := <<1, 63, 64, 65, 127, 128, 129, 1000, 2, 3, 300>>
			from l_pos := 1 until l_pos > a_data.count loop
				l_n := l_sizes [(l_k \\ l_sizes.count) + 1].min (a_data.count - l_pos + 1)
				l_piece := a_data.substring (l_pos, l_pos + l_n - 1)
				inspect l_k \\ 3
				when 0 then
					a_state.update (l_piece)
				when 1 then
					create l_bytes.make_filled (0, 1, l_n)
					from i := 1 until i > l_n loop
						l_bytes [i] := l_piece.code (i).to_natural_8
						i := i + 1
					end
					a_state.update_bytes (l_bytes)
				else
					create l_buffer.make (l_n + 7)
					from i := 1 until i > l_n loop
						l_buffer.put_natural_8 (l_piece.code (i).to_natural_8, i - 1)
						i := i + 1
					end
					a_state.update_from_managed (l_buffer, l_n)
				end
				l_pos := l_pos + l_n
				l_k := l_k + 1
			end
			a_state.finish
		end

	unicode_name: STRING_32
			-- "test_hash_" + Hebrew shalom + "_" + Greek logos + ".txt", built from code points.
		do
			Result := {STRING_32} "test_hash_"
			across <<0x05E9, 0x05DC, 0x05D5, 0x05DD>> as ic loop Result.append_code (ic.to_natural_32) end
			Result.append_character ('_')
			across <<0x03BB, 0x03CC, 0x03B3, 0x03BF, 0x03C2>> as ic loop Result.append_code (ic.to_natural_32) end
			Result.append ({STRING_32} ".txt")
		end

	write_file (a_path: STRING; a_content: STRING)
			-- Write `a_content' byte for byte to `a_path'.
		local
			l_file: RAW_FILE
		do
			create l_file.make_with_name (a_path)
			l_file.open_write
			l_file.put_string (a_content)
			l_file.close
		end

	delete_file (a_path: STRING)
			-- Remove `a_path' if present.
		local
			l_file: RAW_FILE
		do
			create l_file.make_with_name (a_path)
			if l_file.exists then
				l_file.delete
			end
		end

	attached_or_empty (a_value: detachable STRING): STRING
			-- `a_value', or "" for Void (so a Void result fails the comparison).
		do
			if attached a_value as al_value then
				Result := al_value
			else
				Result := ""
			end
		end

end
