-- Copyright (c) 2015  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------
-- base64 tests

local base64 = require "plc.base64"
local be = base64.encode
local bd = base64.decode

local function base64test()
	assert(be"" == "")
	assert(be"a" == "YQ==")
	assert(be"aa" == "YWE=")
	assert(be"aaa" == "YWFh")
	assert(be"aaaa" == "YWFhYQ==")
	assert(be(("a"):rep(61)) ==
		"YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh"
		.. "YWFhYWFhYWFhYWFhYWFh\nYWFhYWFhYQ==")
	assert("" == bd"")
	assert("a" == bd"YQ==")
	assert("aa" == bd"YWE=")
	assert("aaa" == bd"YWFh")
	assert("aaaa" == bd"YWFhYQ==")
	assert(bd"YWFhYWFhYQ" == "aaaaaaa")
	assert(bd"YWF\nhY  W\t\r\nFhYQ" == "aaaaaaa")
	assert(bd(be"\x00\x01\x02\x03\x00" ) == "\x00\x01\x02\x03\x00")

	-- 171103 - add a test for the "n*54-1" bug 
	-- (strings with n*54-1 or n*54-2 bytes)
	for i = 0, 3 do
		local ln = 3 * 54 - i
		local s = ("a"):rep(ln)
		assert(bd(be(s)) == s)
	end

end


base64test()

print("test_base64: ok")
