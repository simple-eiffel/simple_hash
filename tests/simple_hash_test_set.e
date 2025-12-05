note
	description: "Tests for SIMPLE_HASH"
	author: "Larry Rix"
	date: "$Date$"
	revision: "$Revision$"
	testing: "type/manual"

class
	SIMPLE_HASH_TEST_SET

inherit
	TEST_SET_BASE

feature -- Test: SHA-256

	test_sha256_empty
			-- Test SHA-256 of empty string.
		note
			testing: "covers/{SIMPLE_HASH}.sha256"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			-- Known value: SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
			assert_strings_equal ("empty hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hasher.sha256 (""))
		end

	test_sha256_hello
			-- Test SHA-256 of "hello".
		note
			testing: "covers/{SIMPLE_HASH}.sha256"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			-- Known value: SHA256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
			assert_strings_equal ("hello hash", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", hasher.sha256 ("hello"))
		end

	test_sha256_hello_world
			-- Test SHA-256 of "Hello, World!".
		note
			testing: "covers/{SIMPLE_HASH}.sha256"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			-- Known value: SHA256("Hello, World!") = dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f
			assert_strings_equal ("Hello World hash", "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f", hasher.sha256 ("Hello, World!"))
		end

	test_sha256_quick_brown_fox
			-- Test SHA-256 of the classic pangram.
		note
			testing: "covers/{SIMPLE_HASH}.sha256"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			-- Known value for "The quick brown fox jumps over the lazy dog"
			assert_strings_equal ("pangram hash", "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592", hasher.sha256 ("The quick brown fox jumps over the lazy dog"))
		end

	test_sha256_bytes_length
			-- Test SHA-256 returns 32 bytes.
		note
			testing: "covers/{SIMPLE_HASH}.sha256_bytes"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			assert_integers_equal ("32 bytes", 32, hasher.sha256_bytes ("test").count)
		end

	test_sha256_hex_length
			-- Test SHA-256 hex string is 64 characters.
		note
			testing: "covers/{SIMPLE_HASH}.sha256"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			assert_integers_equal ("64 chars", 64, hasher.sha256 ("test").count)
		end

feature -- Test: HMAC-SHA256

	test_hmac_sha256_rfc4231_1
			-- Test HMAC-SHA256 with RFC 4231 test vector 1.
		note
			testing: "covers/{SIMPLE_HASH}.hmac_sha256"
		local
			hasher: SIMPLE_HASH
			key, data: STRING
		do
			create hasher.make
			-- Test Case 1 from RFC 4231
			-- Key = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (20 bytes)
			-- Data = "Hi There"
			key := "%/11/%/11/%/11/%/11/%/11/%/11/%/11/%/11/%/11/%/11/%/11/%/11/%/11/%/11/%/11/%/11/%/11/%/11/%/11/%/11/"
			data := "Hi There"
			assert_strings_equal ("rfc4231 test 1", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", hasher.hmac_sha256 (key, data))
		end

	test_hmac_sha256_rfc4231_2
			-- Test HMAC-SHA256 with RFC 4231 test vector 2.
		note
			testing: "covers/{SIMPLE_HASH}.hmac_sha256"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			-- Test Case 2: Key = "Jefe", Data = "what do ya want for nothing?"
			assert_strings_equal ("rfc4231 test 2", "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", hasher.hmac_sha256 ("Jefe", "what do ya want for nothing?"))
		end

	test_hmac_sha256_empty_message
			-- Test HMAC-SHA256 with empty message.
		note
			testing: "covers/{SIMPLE_HASH}.hmac_sha256"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			-- HMAC-SHA256("key", "") = known value
			assert_strings_equal ("empty message", "5d5d139563c95b5967b9bd9a8c9b233a9dedb45072794cd232dc1b74832607d0", hasher.hmac_sha256 ("key", ""))
		end

	test_hmac_sha256_bytes_length
			-- Test HMAC-SHA256 returns 32 bytes.
		note
			testing: "covers/{SIMPLE_HASH}.hmac_sha256_bytes"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			assert_integers_equal ("32 bytes", 32, hasher.hmac_sha256_bytes ("secret", "message").count)
		end

	test_hmac_sha256_hex_length
			-- Test HMAC-SHA256 hex string is 64 characters.
		note
			testing: "covers/{SIMPLE_HASH}.hmac_sha256"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			assert_integers_equal ("64 chars", 64, hasher.hmac_sha256 ("secret", "message").count)
		end

feature -- Test: MD5

	test_md5_empty
			-- Test MD5 of empty string.
		note
			testing: "covers/{SIMPLE_HASH}.md5"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			-- Known value: MD5("") = d41d8cd98f00b204e9800998ecf8427e
			assert_strings_equal ("empty md5", "d41d8cd98f00b204e9800998ecf8427e", hasher.md5 (""))
		end

	test_md5_hello
			-- Test MD5 of "hello".
		note
			testing: "covers/{SIMPLE_HASH}.md5"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			-- Known value: MD5("hello") = 5d41402abc4b2a76b9719d911017c592
			assert_strings_equal ("hello md5", "5d41402abc4b2a76b9719d911017c592", hasher.md5 ("hello"))
		end

	test_md5_hello_world
			-- Test MD5 of "Hello, World!".
		note
			testing: "covers/{SIMPLE_HASH}.md5"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			-- Known value: MD5("Hello, World!") = 65a8e27d8879283831b664bd8b7f0ad4
			assert_strings_equal ("Hello World md5", "65a8e27d8879283831b664bd8b7f0ad4", hasher.md5 ("Hello, World!"))
		end

	test_md5_quick_brown_fox
			-- Test MD5 of the classic pangram.
		note
			testing: "covers/{SIMPLE_HASH}.md5"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			-- Known value: MD5("The quick brown fox jumps over the lazy dog") = 9e107d9d372bb6826bd81d3542a419d6
			assert_strings_equal ("pangram md5", "9e107d9d372bb6826bd81d3542a419d6", hasher.md5 ("The quick brown fox jumps over the lazy dog"))
		end

	test_md5_bytes_length
			-- Test MD5 returns 16 bytes.
		note
			testing: "covers/{SIMPLE_HASH}.md5_bytes"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			assert_integers_equal ("16 bytes", 16, hasher.md5_bytes ("test").count)
		end

	test_md5_hex_length
			-- Test MD5 hex string is 32 characters.
		note
			testing: "covers/{SIMPLE_HASH}.md5"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			assert_integers_equal ("32 chars", 32, hasher.md5 ("test").count)
		end

feature -- Test: Utilities

	test_bytes_to_hex
			-- Test bytes to hex conversion.
		note
			testing: "covers/{SIMPLE_HASH}.bytes_to_hex"
		local
			hasher: SIMPLE_HASH
			bytes: ARRAY [NATURAL_8]
		do
			create hasher.make
			bytes := <<0, 255, 16, 171>>
			assert_strings_equal ("bytes to hex", "00ff10ab", hasher.bytes_to_hex (bytes))
		end

	test_hex_to_bytes
			-- Test hex to bytes conversion.
		note
			testing: "covers/{SIMPLE_HASH}.hex_to_bytes"
		local
			hasher: SIMPLE_HASH
			bytes: ARRAY [NATURAL_8]
		do
			create hasher.make
			bytes := hasher.hex_to_bytes ("00ff10ab")
			assert_integers_equal ("byte 1", 0, bytes [1].to_integer_32)
			assert_integers_equal ("byte 2", 255, bytes [2].to_integer_32)
			assert_integers_equal ("byte 3", 16, bytes [3].to_integer_32)
			assert_integers_equal ("byte 4", 171, bytes [4].to_integer_32)
		end

	test_hex_roundtrip
			-- Test hex conversion roundtrip.
		note
			testing: "covers/{SIMPLE_HASH}.bytes_to_hex", "covers/{SIMPLE_HASH}.hex_to_bytes"
		local
			hasher: SIMPLE_HASH
			original: ARRAY [NATURAL_8]
			hex: STRING
			roundtrip: ARRAY [NATURAL_8]
		do
			create hasher.make
			original := <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>
			hex := hasher.bytes_to_hex (original)
			roundtrip := hasher.hex_to_bytes (hex)
			assert_integers_equal ("same count", original.count, roundtrip.count)
			assert ("same content", across 1 |..| original.count as i all original [i.item] = roundtrip [i.item] end)
		end

end
