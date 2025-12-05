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
		do
			print ("simple_hash test runner%N")
			print ("Run tests via EiffelStudio AutoTest%N")
		end

end
