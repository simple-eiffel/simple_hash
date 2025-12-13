note
	description: "Tests for SIMPLE_HASH"
	author: "Larry Rix"
	date: "$Date$"
	revision: "$Revision$"
	testing: "covers"

class
	LIB_TESTS

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

feature -- Test: Secure Comparison (Constant-Time)

	test_secure_compare_equal_strings
			-- Test secure_compare with equal strings.
		note
			testing: "covers/{SIMPLE_HASH}.secure_compare"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			assert ("equal strings", hasher.secure_compare ("secret_token", "secret_token"))
			assert ("equal empty", hasher.secure_compare ("", ""))
			assert ("equal single char", hasher.secure_compare ("a", "a"))
		end

	test_secure_compare_different_strings
			-- Test secure_compare with different strings of same length.
		note
			testing: "covers/{SIMPLE_HASH}.secure_compare"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			assert ("first char different", not hasher.secure_compare ("abc", "xbc"))
			assert ("last char different", not hasher.secure_compare ("abc", "abx"))
			assert ("middle char different", not hasher.secure_compare ("abc", "axc"))
		end

	test_secure_compare_different_lengths
			-- Test secure_compare with different length strings.
		note
			testing: "covers/{SIMPLE_HASH}.secure_compare"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			assert ("different lengths 1", not hasher.secure_compare ("short", "longer_string"))
			assert ("different lengths 2", not hasher.secure_compare ("longer_string", "short"))
			assert ("empty vs non-empty", not hasher.secure_compare ("", "a"))
			assert ("non-empty vs empty", not hasher.secure_compare ("a", ""))
		end

	test_secure_compare_bytes_equal
			-- Test secure_compare_bytes with equal byte arrays.
		note
			testing: "covers/{SIMPLE_HASH}.secure_compare_bytes"
		local
			hasher: SIMPLE_HASH
			a, b: ARRAY [NATURAL_8]
		do
			create hasher.make
			a := <<1, 2, 3, 4, 5>>
			b := <<1, 2, 3, 4, 5>>
			assert ("equal byte arrays", hasher.secure_compare_bytes (a, b))
		end

	test_secure_compare_bytes_different
			-- Test secure_compare_bytes with different byte arrays.
		note
			testing: "covers/{SIMPLE_HASH}.secure_compare_bytes"
		local
			hasher: SIMPLE_HASH
			a, b: ARRAY [NATURAL_8]
		do
			create hasher.make
			a := <<1, 2, 3, 4, 5>>
			b := <<1, 2, 3, 4, 6>>
			assert ("different last byte", not hasher.secure_compare_bytes (a, b))

			a := <<1, 2, 3, 4, 5>>
			b := <<0, 2, 3, 4, 5>>
			assert ("different first byte", not hasher.secure_compare_bytes (a, b))
		end

	test_secure_compare_bytes_different_lengths
			-- Test secure_compare_bytes with different length arrays.
		note
			testing: "covers/{SIMPLE_HASH}.secure_compare_bytes"
		local
			hasher: SIMPLE_HASH
			a, b: ARRAY [NATURAL_8]
		do
			create hasher.make
			a := <<1, 2, 3>>
			b := <<1, 2, 3, 4, 5>>
			assert ("different lengths", not hasher.secure_compare_bytes (a, b))
		end

	test_secure_compare_hex_equal
			-- Test secure_compare_hex with equal hex strings.
		note
			testing: "covers/{SIMPLE_HASH}.secure_compare_hex"
		local
			hasher: SIMPLE_HASH
			hmac1, hmac2: STRING
		do
			create hasher.make
			-- Compute same HMAC twice - should compare equal
			hmac1 := hasher.hmac_sha256 ("secret", "message")
			hmac2 := hasher.hmac_sha256 ("secret", "message")
			assert ("same hmacs", hasher.secure_compare_hex (hmac1, hmac2))
		end

	test_secure_compare_hex_different
			-- Test secure_compare_hex with different hex strings.
		note
			testing: "covers/{SIMPLE_HASH}.secure_compare_hex"
		local
			hasher: SIMPLE_HASH
			hmac1, hmac2: STRING
		do
			create hasher.make
			-- Compute different HMACs - should not compare equal
			hmac1 := hasher.hmac_sha256 ("secret", "message1")
			hmac2 := hasher.hmac_sha256 ("secret", "message2")
			assert ("different hmacs", not hasher.secure_compare_hex (hmac1, hmac2))
		end

	test_secure_compare_case_sensitivity
			-- Test that secure_compare is case-sensitive.
		note
			testing: "covers/{SIMPLE_HASH}.secure_compare"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			assert ("case sensitive", not hasher.secure_compare ("ABC", "abc"))
			assert ("case sensitive 2", not hasher.secure_compare ("Secret", "secret"))
		end

feature -- Test: SHA-512

	test_sha512_empty
			-- Test SHA-512 of empty string.
		note
			testing: "covers/{SIMPLE_HASH}.sha512"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			-- Known value: SHA512("") = cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
			assert_strings_equal ("empty hash", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", hasher.sha512 (""))
		end

	test_sha512_hello
			-- Test SHA-512 of "hello".
		note
			testing: "covers/{SIMPLE_HASH}.sha512"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			-- Known value: SHA512("hello") = 9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043
			assert_strings_equal ("hello hash", "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043", hasher.sha512 ("hello"))
		end

	test_sha512_hello_world
			-- Test SHA-512 of "Hello, World!".
		note
			testing: "covers/{SIMPLE_HASH}.sha512"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			-- Known value: SHA512("Hello, World!") = 374d794a95cdcfd8b35993185fef9ba368f160d8daf432d08ba9f1ed1e5abe6cc69291e0fa2fe0006a52570ef18c19def4e617c33ce52ef0a6e5fbe318cb0387
			assert_strings_equal ("Hello World hash", "374d794a95cdcfd8b35993185fef9ba368f160d8daf432d08ba9f1ed1e5abe6cc69291e0fa2fe0006a52570ef18c19def4e617c33ce52ef0a6e5fbe318cb0387", hasher.sha512 ("Hello, World!"))
		end

	test_sha512_quick_brown_fox
			-- Test SHA-512 of the classic pangram.
		note
			testing: "covers/{SIMPLE_HASH}.sha512"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			-- Known value for "The quick brown fox jumps over the lazy dog"
			assert_strings_equal ("pangram hash", "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6", hasher.sha512 ("The quick brown fox jumps over the lazy dog"))
		end

	test_sha512_bytes_length
			-- Test SHA-512 returns 64 bytes.
		note
			testing: "covers/{SIMPLE_HASH}.sha512_bytes"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			assert_integers_equal ("64 bytes", 64, hasher.sha512_bytes ("test").count)
		end

	test_sha512_hex_length
			-- Test SHA-512 hex string is 128 characters.
		note
			testing: "covers/{SIMPLE_HASH}.sha512"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			assert_integers_equal ("128 chars", 128, hasher.sha512 ("test").count)
		end

feature -- Test: HMAC-SHA512

	test_hmac_sha512_rfc4231_1
			-- Test HMAC-SHA512 with RFC 4231 test vector 1.
		note
			testing: "covers/{SIMPLE_HASH}.hmac_sha512"
		local
			hasher: SIMPLE_HASH
			key, data: STRING
		do
			create hasher.make
			-- Test Case 1 from RFC 4231 (for HMAC-SHA512)
			-- Key = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (20 bytes)
			-- Data = "Hi There"
			key := "%/11/%/11/%/11/%/11/%/11/%/11/%/11/%/11/%/11/%/11/%/11/%/11/%/11/%/11/%/11/%/11/%/11/%/11/%/11/%/11/"
			data := "Hi There"
			assert_strings_equal ("rfc4231 test 1", "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854", hasher.hmac_sha512 (key, data))
		end

	test_hmac_sha512_rfc4231_2
			-- Test HMAC-SHA512 with RFC 4231 test vector 2.
		note
			testing: "covers/{SIMPLE_HASH}.hmac_sha512"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			-- Test Case 2: Key = "Jefe", Data = "what do ya want for nothing?"
			assert_strings_equal ("rfc4231 test 2", "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737", hasher.hmac_sha512 ("Jefe", "what do ya want for nothing?"))
		end

	test_hmac_sha512_bytes_length
			-- Test HMAC-SHA512 returns 64 bytes.
		note
			testing: "covers/{SIMPLE_HASH}.hmac_sha512_bytes"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			assert_integers_equal ("64 bytes", 64, hasher.hmac_sha512_bytes ("secret", "message").count)
		end

	test_hmac_sha512_hex_length
			-- Test HMAC-SHA512 hex string is 128 characters.
		note
			testing: "covers/{SIMPLE_HASH}.hmac_sha512"
		local
			hasher: SIMPLE_HASH
		do
			create hasher.make
			assert_integers_equal ("128 chars", 128, hasher.hmac_sha512 ("secret", "message").count)
		end

feature -- Test: File Hashing

	test_sha256_file
			-- Test SHA-256 file hashing.
		note
			testing: "covers/{SIMPLE_HASH}.sha256_file"
		local
			hasher: SIMPLE_HASH
			l_file: PLAIN_TEXT_FILE
			l_path: STRING
			l_result: detachable STRING
		do
			create hasher.make
			l_path := "test_hash_file.txt"
			-- Create test file with known content
			create l_file.make_create_read_write (l_path)
			l_file.put_string ("Hello, World!")
			l_file.close
			-- Hash the file
			l_result := hasher.sha256_file (l_path)
			-- Clean up
			create l_file.make_with_name (l_path)
			l_file.delete
			-- Verify - SHA256("Hello, World!") = dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f
			assert ("result not void", l_result /= Void)
			if attached l_result as r then
				assert_strings_equal ("file hash", "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f", r)
			end
		end

	test_sha512_file
			-- Test SHA-512 file hashing.
		note
			testing: "covers/{SIMPLE_HASH}.sha512_file"
		local
			hasher: SIMPLE_HASH
			l_file: PLAIN_TEXT_FILE
			l_path: STRING
			l_result: detachable STRING
		do
			create hasher.make
			l_path := "test_hash_file512.txt"
			-- Create test file with known content
			create l_file.make_create_read_write (l_path)
			l_file.put_string ("Hello, World!")
			l_file.close
			-- Hash the file
			l_result := hasher.sha512_file (l_path)
			-- Clean up
			create l_file.make_with_name (l_path)
			l_file.delete
			-- Verify - SHA512("Hello, World!")
			assert ("result not void", l_result /= Void)
			if attached l_result as r then
				assert_strings_equal ("file hash", "374d794a95cdcfd8b35993185fef9ba368f160d8daf432d08ba9f1ed1e5abe6cc69291e0fa2fe0006a52570ef18c19def4e617c33ce52ef0a6e5fbe318cb0387", r)
			end
		end

	test_md5_file
			-- Test MD5 file hashing.
		note
			testing: "covers/{SIMPLE_HASH}.md5_file"
		local
			hasher: SIMPLE_HASH
			l_file: PLAIN_TEXT_FILE
			l_path: STRING
			l_result: detachable STRING
		do
			create hasher.make
			l_path := "test_hash_file_md5.txt"
			-- Create test file with known content
			create l_file.make_create_read_write (l_path)
			l_file.put_string ("Hello, World!")
			l_file.close
			-- Hash the file
			l_result := hasher.md5_file (l_path)
			-- Clean up
			create l_file.make_with_name (l_path)
			l_file.delete
			-- Verify - MD5("Hello, World!") = 65a8e27d8879283831b664bd8b7f0ad4
			assert ("result not void", l_result /= Void)
			if attached l_result as r then
				assert_strings_equal ("file hash", "65a8e27d8879283831b664bd8b7f0ad4", r)
			end
		end

	test_sha256_file_not_found
			-- Test SHA-256 file hashing with non-existent file.
		note
			testing: "covers/{SIMPLE_HASH}.sha256_file"
		local
			hasher: SIMPLE_HASH
			l_result: detachable STRING
		do
			create hasher.make
			l_result := hasher.sha256_file ("non_existent_file_12345.txt")
			assert ("void for non-existent", l_result = Void)
		end

	test_sha256_file_matches_string
			-- Test that file hash matches string hash for same content.
		note
			testing: "covers/{SIMPLE_HASH}.sha256_file"
		local
			hasher: SIMPLE_HASH
			l_file: PLAIN_TEXT_FILE
			l_path, l_content: STRING
			l_file_result, l_string_result: detachable STRING
		do
			create hasher.make
			l_path := "test_hash_match.txt"
			l_content := "The quick brown fox jumps over the lazy dog"
			-- Create test file
			create l_file.make_create_read_write (l_path)
			l_file.put_string (l_content)
			l_file.close
			-- Hash both ways
			l_file_result := hasher.sha256_file (l_path)
			l_string_result := hasher.sha256 (l_content)
			-- Clean up
			create l_file.make_with_name (l_path)
			l_file.delete
			-- Verify match
			assert ("file result not void", l_file_result /= Void)
			if attached l_file_result as fr then
				assert_strings_equal ("file matches string", l_string_result, fr)
			end
		end

end
