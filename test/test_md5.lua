-- Copyright (c) 2017  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------
-- md5 tests

local md5 = require "plc.md5"
local bin = require "plc.bin"

local xts = bin.hextos

-- test vectors from RFC 1321 - https://www.ietf.org/rfc/rfc1321.txt

local function test_md5()
	local hash = md5.hash
	assert(hash("") == xts("d41d8cd98f00b204e9800998ecf8427e"))
	assert(hash("a") == xts("0cc175b9c0f1b6a831c399e269772661"))
	assert(hash("abc") == xts("900150983cd24fb0d6963f7d28e17f72"))
	assert(hash("message digest") == xts("f96b697d7cb7938d525a2f31aaf161d0"))
	assert(hash("abcdefghijklmnopqrstuvwxyz")
		== xts("c3fcd3d76192e4007dfb496cca67e13b"))
	assert(hash(
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
		== xts("d174ab98d277d9f5a5611c2c9f419d9f"))
	assert(hash("1234567890123456789012345678901234567890"
			.. "1234567890123456789012345678901234567890")
		== xts("57edf4a22be3c955ac49da2e2107b67a"))
end

test_md5()

