note
	description: "Test application for simple_hash"
	author: "Larry Rix"

class
	SSC_TEST_APP

create
	make

feature {NONE} -- Initialization

	make
			-- Run tests.
		local
			tests: SIMPLE_HASH_TEST_SET
		do
			create tests
			print ("simple_hash test runner%N")
			print ("========================%N%N")

			passed := 0
			failed := 0

			-- SHA-256
			run_test (agent tests.test_sha256_empty, "test_sha256_empty")
			run_test (agent tests.test_sha256_hello, "test_sha256_hello")
			run_test (agent tests.test_sha256_hello_world, "test_sha256_hello_world")
			run_test (agent tests.test_sha256_quick_brown_fox, "test_sha256_quick_brown_fox")
			run_test (agent tests.test_sha256_bytes_length, "test_sha256_bytes_length")
			run_test (agent tests.test_sha256_hex_length, "test_sha256_hex_length")

			-- HMAC-SHA256
			run_test (agent tests.test_hmac_sha256_rfc4231_1, "test_hmac_sha256_rfc4231_1")
			run_test (agent tests.test_hmac_sha256_rfc4231_2, "test_hmac_sha256_rfc4231_2")
			run_test (agent tests.test_hmac_sha256_empty_message, "test_hmac_sha256_empty_message")
			run_test (agent tests.test_hmac_sha256_bytes_length, "test_hmac_sha256_bytes_length")
			run_test (agent tests.test_hmac_sha256_hex_length, "test_hmac_sha256_hex_length")

			-- MD5
			run_test (agent tests.test_md5_empty, "test_md5_empty")
			run_test (agent tests.test_md5_hello, "test_md5_hello")
			run_test (agent tests.test_md5_hello_world, "test_md5_hello_world")
			run_test (agent tests.test_md5_quick_brown_fox, "test_md5_quick_brown_fox")
			run_test (agent tests.test_md5_bytes_length, "test_md5_bytes_length")
			run_test (agent tests.test_md5_hex_length, "test_md5_hex_length")

			-- Utilities
			run_test (agent tests.test_bytes_to_hex, "test_bytes_to_hex")
			run_test (agent tests.test_hex_to_bytes, "test_hex_to_bytes")
			run_test (agent tests.test_hex_roundtrip, "test_hex_roundtrip")

			-- Secure Comparison
			run_test (agent tests.test_secure_compare_equal_strings, "test_secure_compare_equal_strings")
			run_test (agent tests.test_secure_compare_different_strings, "test_secure_compare_different_strings")
			run_test (agent tests.test_secure_compare_different_lengths, "test_secure_compare_different_lengths")
			run_test (agent tests.test_secure_compare_bytes_equal, "test_secure_compare_bytes_equal")
			run_test (agent tests.test_secure_compare_bytes_different, "test_secure_compare_bytes_different")
			run_test (agent tests.test_secure_compare_bytes_different_lengths, "test_secure_compare_bytes_different_lengths")
			run_test (agent tests.test_secure_compare_hex_equal, "test_secure_compare_hex_equal")
			run_test (agent tests.test_secure_compare_hex_different, "test_secure_compare_hex_different")
			run_test (agent tests.test_secure_compare_case_sensitivity, "test_secure_compare_case_sensitivity")

			-- SHA-512
			run_test (agent tests.test_sha512_empty, "test_sha512_empty")
			run_test (agent tests.test_sha512_hello, "test_sha512_hello")
			run_test (agent tests.test_sha512_hello_world, "test_sha512_hello_world")
			run_test (agent tests.test_sha512_quick_brown_fox, "test_sha512_quick_brown_fox")
			run_test (agent tests.test_sha512_bytes_length, "test_sha512_bytes_length")
			run_test (agent tests.test_sha512_hex_length, "test_sha512_hex_length")

			-- HMAC-SHA512
			run_test (agent tests.test_hmac_sha512_rfc4231_1, "test_hmac_sha512_rfc4231_1")
			run_test (agent tests.test_hmac_sha512_rfc4231_2, "test_hmac_sha512_rfc4231_2")
			run_test (agent tests.test_hmac_sha512_bytes_length, "test_hmac_sha512_bytes_length")
			run_test (agent tests.test_hmac_sha512_hex_length, "test_hmac_sha512_hex_length")

			-- File Hashing
			run_test (agent tests.test_sha256_file, "test_sha256_file")
			run_test (agent tests.test_sha512_file, "test_sha512_file")
			run_test (agent tests.test_md5_file, "test_md5_file")
			run_test (agent tests.test_sha256_file_not_found, "test_sha256_file_not_found")
			run_test (agent tests.test_sha256_file_matches_string, "test_sha256_file_matches_string")

			print ("%N========================%N")
			print ("Results: " + passed.out + " passed, " + failed.out + " failed%N")

			if failed > 0 then
				print ("TESTS FAILED%N")
			else
				print ("ALL TESTS PASSED%N")
			end
		end

feature {NONE} -- Implementation

	passed: INTEGER
	failed: INTEGER

	run_test (a_test: PROCEDURE; a_name: STRING)
			-- Run a single test and update counters.
		local
			l_retried: BOOLEAN
		do
			if not l_retried then
				a_test.call (Void)
				print ("  PASS: " + a_name + "%N")
				passed := passed + 1
			end
		rescue
			print ("  FAIL: " + a_name + "%N")
			failed := failed + 1
			l_retried := True
			retry
		end

end
