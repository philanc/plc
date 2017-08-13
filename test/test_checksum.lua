-- Copyright (c) 2015  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------
-- checksum tests

local checksum = require "plc.checksum"


local function test_checksum()
	-- test values at wikipedia
	-- checked with checksum on https://quickhash.com/

	local sfox = "The quick brown fox jumps over the lazy dog"

	-- crc32
	assert(checksum.crc32(sfox) == 0x414fa339 )
		-- 0x414fa339 matches crc32-b on quickhash.com, not crc32 (?!?)
	assert(checksum.crc32_nt(sfox) == 0x414fa339 )

	-- adler32
	assert(checksum.adler32(sfox) == 0x5bdc0fda )
	assert(checksum.adler32("Wikipedia") == 0x11e60398 )
end


test_checksum()

print("test_checksum: ok")
