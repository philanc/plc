-- Copyright (c) 2015  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------
-- base58 tests

local base58 = require "plc.base58"

local function base58test()

	assert(base58.encode('\x01') == '2')
	assert(base58.encode('\x00\x01') == '12')
	assert(base58.encode('') == '')
	assert(base58.encode('\0\0') == '11')
	assert(base58.encode('o hai') == 'DYB3oMS') --[1]
	local x1 = "\x00\x01\x09\x66\x77\x60\x06\x95\x3D\x55\x67\x43"
		.. "\x9E\x5E\x39\xF8\x6A\x0D\x27\x3B\xEE\xD6\x19\x67\xF6"
	local e1 = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM" --[2]
	assert(base58.encode(x1) == e1)
	local x2 = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
		.. "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
	local e2 = "thX6LZfHDZZKUs92febYZhYRcXddmzfzF2NvTkPNE" --[3]
	assert(base58.encode(x2) == e2)

	assert(base58.decode('') == '')
	assert(base58.decode('11') == '\0\0')
	assert(base58.decode('DYB3oMS') == 'o hai')
	assert(base58.decode(e1) == x1)
	assert(base58.decode(e2) == x2)

end--base58test()

base58test()
print("test_base58: ok")
