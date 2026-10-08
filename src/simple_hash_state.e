note
	description: "[
		Incremental (streaming) message digest.

		Feed the message in any number of pieces - `update' (a string),
		`update_bytes' (an array) or `update_from_managed' (a C-heap buffer,
		the zero-copy path used for files) - then `finish' and read `digest'.
		Memory stays constant whatever the message length: only one partial
		block is ever held between calls.

		Block compression runs in inline C on C-heap memory only (the
		chaining value, the partial block and every input buffer live in
		MANAGED_POINTERs, which the garbage collector never moves), so each
		compression external is declared `C blocking' and a long hash never
		holds up a collection on another processor.

		Usage:
			create {SIMPLE_SHA256_STATE} l_state.make
			l_state.update ("abc")
			l_state.finish
			print (l_state.digest_hex)  -- ba7816bf...
	]"
	author: "Larry Rix"
	date: "$Date$"
	revision: "$Revision$"

deferred class
	SIMPLE_HASH_STATE

feature {NONE} -- Initialization

	make
			-- Start a fresh digest.
		do
			create pending.make (block_size)
			create chaining.make (chaining_size)
			create digest.make_empty
			reset
		ensure
			fresh: byte_count = 0 and not is_finished
			nothing_pending: pending_count = 0
		end

feature -- Access

	digest: ARRAY [NATURAL_8]
			-- Digest of every byte fed since the last `reset'; empty until `is_finished'.

	digest_hex: STRING
			-- `digest' as lowercase hex.
		require
			finished: is_finished
		local
			l_hex: STRING
		do
			l_hex := "0123456789abcdef"
			create Result.make (digest.count * 2)
			across digest as ic loop
				Result.append_character (l_hex [(ic |>> 4).to_integer_32 + 1])
				Result.append_character (l_hex [(ic & 0x0F).to_integer_32 + 1])
			end
		ensure
			correct_length: Result.count = digest_size * 2
		end

	byte_count: NATURAL_64
			-- Number of message bytes fed since the last `reset'.

feature -- Measurement

	block_size: INTEGER
			-- Bytes per compression block.
		deferred
		ensure
			positive: Result > 0
		end

	digest_size: INTEGER
			-- Bytes in the finished digest.
		deferred
		ensure
			positive: Result > 0
		end

feature -- Status report

	is_finished: BOOLEAN
			-- Has `finish' run since the last `reset'?

feature -- Element change

	reset
			-- Forget everything fed and start a fresh digest.
		do
			pending_count := 0
			byte_count := 0
			is_finished := False
			create digest.make_empty
			load_initial_chaining
		ensure
			fresh: byte_count = 0 and not is_finished
			nothing_pending: pending_count = 0
			no_digest: digest.is_empty
		end

	update (a_data: READABLE_STRING_8)
			-- Feed the bytes (character codes) of `a_data'.
		require
			not_finished: not is_finished
		local
			l_scratch: MANAGED_POINTER
			l_area: ANY
			l_done, l_n, i: INTEGER
		do
			if a_data.count > 0 then
				l_scratch := scratch_for (a_data.count)
				from
					l_done := 0
				until
					l_done = a_data.count
				loop
					l_n := (a_data.count - l_done).min (l_scratch.count)
					if attached {STRING_8} a_data as al_string then
							-- `to_c' answers the character area; it is copied to C-heap
							-- memory at once, before anything can allocate (and so move it).
						l_area := al_string.to_c
						l_scratch.item.memory_copy ($l_area + l_done, l_n)
					else
						from i := 1 until i > l_n loop
							l_scratch.put_natural_8 (a_data.code (l_done + i).to_natural_8, i - 1)
							i := i + 1
						variant
							l_n + 1 - i
						end
					end
					absorb (l_scratch.item, l_n)
					l_done := l_done + l_n
				variant
					a_data.count - l_done
				end
			end
		ensure
			counted: byte_count = old byte_count + a_data.count.to_natural_64
			still_open: not is_finished
		end

	update_bytes (a_bytes: ARRAY [NATURAL_8])
			-- Feed `a_bytes'.
		require
			not_finished: not is_finished
		local
			l_scratch: MANAGED_POINTER
			l_area: ANY
			l_done, l_n: INTEGER
		do
			if a_bytes.count > 0 then
				l_scratch := scratch_for (a_bytes.count)
				from
					l_done := 0
				until
					l_done = a_bytes.count
				loop
					l_n := (a_bytes.count - l_done).min (l_scratch.count)
					l_area := a_bytes.to_c
					l_scratch.item.memory_copy ($l_area + l_done, l_n)
					absorb (l_scratch.item, l_n)
					l_done := l_done + l_n
				variant
					a_bytes.count - l_done
				end
			end
		ensure
			counted: byte_count = old byte_count + a_bytes.count.to_natural_64
			still_open: not is_finished
		end

	update_from_managed (a_buffer: MANAGED_POINTER; a_count: INTEGER)
			-- Feed the first `a_count' bytes of `a_buffer' (no copy).
		require
			not_finished: not is_finished
			count_non_negative: a_count >= 0
			count_in_buffer: a_count <= a_buffer.count
		do
			if a_count > 0 then
				absorb (a_buffer.item, a_count)
			end
		ensure
			counted: byte_count = old byte_count + a_count.to_natural_64
			still_open: not is_finished
		end

feature -- Basic operations

	finish
			-- Pad the message, run the last block(s) and make `digest' available.
		require
			not_finished: not is_finished
		local
			l_tail: MANAGED_POINTER
			l_total: INTEGER
			l_bits_low, l_bits_high: NATURAL_64
		do
			create l_tail.make (block_size * 2)
			if pending_count > 0 then
				l_tail.item.memory_copy (pending.item, pending_count)
			end
			l_tail.put_natural_8 (0x80, pending_count)
			if pending_count + 1 + length_field_size <= block_size then
				l_total := block_size
			else
				l_total := block_size * 2
			end
			l_bits_low := byte_count |<< 3
			l_bits_high := byte_count |>> 61
			if is_length_big_endian then
				l_tail.put_natural_64_be (l_bits_low, l_total - 8)
				if length_field_size = 16 then
					l_tail.put_natural_64_be (l_bits_high, l_total - 16)
				end
			else
				l_tail.put_natural_64_le (l_bits_low, l_total - 8)
			end
			compress_blocks (chaining.item, l_tail.item, l_total // block_size)
			pending_count := 0
			digest := chaining_digest
			is_finished := True
		ensure
			finished: is_finished
			sized: digest.count = digest_size
			count_kept: byte_count = old byte_count
		end

feature {NONE} -- Implementation

	pending: MANAGED_POINTER
			-- The partial block carried between updates (C heap).

	pending_count: INTEGER
			-- Bytes held in `pending'.

	chaining: MANAGED_POINTER
			-- Chaining value (native-endian words), C heap.

	scratch: detachable MANAGED_POINTER
			-- Reusable C-heap staging buffer for `update' and `update_bytes'.

	Scratch_limit: INTEGER = 65536
			-- Largest staging buffer.

	scratch_for (a_count: INTEGER): MANAGED_POINTER
			-- A staging buffer of at least `a_count'.min (`Scratch_limit') bytes.
		require
			positive: a_count > 0
		do
			if attached scratch as al_scratch and then al_scratch.count >= a_count.min (Scratch_limit) then
				Result := al_scratch
			else
				create Result.make (a_count.min (Scratch_limit))
				scratch := Result
			end
		ensure
			big_enough: Result.count >= a_count.min (Scratch_limit)
		end

	absorb (a_data: POINTER; a_count: INTEGER)
			-- Feed `a_count' bytes at `a_data' (C-heap memory, never movable).
		require
			data_exists: a_data /= default_pointer
			positive: a_count > 0
		local
			l_offset, l_take, l_blocks, l_rest: INTEGER
		do
			if pending_count > 0 then
				l_take := (block_size - pending_count).min (a_count)
				(pending.item + pending_count).memory_copy (a_data, l_take)
				pending_count := pending_count + l_take
				l_offset := l_take
				if pending_count = block_size then
					compress_blocks (chaining.item, pending.item, 1)
					pending_count := 0
				end
			end
			if pending_count = 0 then
				l_blocks := (a_count - l_offset) // block_size
				if l_blocks > 0 then
					compress_blocks (chaining.item, a_data + l_offset, l_blocks)
					l_offset := l_offset + l_blocks * block_size
				end
				l_rest := a_count - l_offset
				if l_rest > 0 then
					pending.item.memory_copy (a_data + l_offset, l_rest)
					pending_count := l_rest
				end
			end
			byte_count := byte_count + a_count.to_natural_64
		ensure
			counted: byte_count = old byte_count + a_count.to_natural_64
			partial_block_only: pending_count >= 0 and pending_count < block_size
		end

	chaining_size: INTEGER
			-- Bytes of chaining value.
		deferred
		ensure
			positive: Result > 0
		end

	length_field_size: INTEGER
			-- Bytes of the message-length field in the padding (8 or 16).
		deferred
		ensure
			valid: Result = 8 or Result = 16
		end

	is_length_big_endian: BOOLEAN
			-- Is the length field (and the digest) big-endian?
		deferred
		end

	load_initial_chaining
			-- Put the algorithm's initial chaining value in `chaining'.
		deferred
		end

	compress_blocks (a_state, a_data: POINTER; a_blocks: INTEGER)
			-- Run `a_blocks' whole blocks at `a_data' through the chaining value at `a_state'.
			-- Both must be C-heap memory: effective versions are `C blocking' externals.
		require
			state_exists: a_state /= default_pointer
			data_exists: a_data /= default_pointer
			positive: a_blocks > 0
		deferred
		end

	chaining_digest: ARRAY [NATURAL_8]
			-- Digest bytes serialized from `chaining'.
		deferred
		ensure
			sized: Result.count = digest_size
		end

invariant
	pending_sized: pending.count = block_size
	chaining_sized: chaining.count = chaining_size
	partial_block_only: pending_count >= 0 and pending_count < block_size
	digest_when_finished: is_finished implies digest.count = digest_size

note
	copyright: "Copyright (c) 2024-2026, Larry Rix"
	license: "MIT License"

end
