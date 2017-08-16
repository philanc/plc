-- Copyright (c) 2017  Pierre Chapuis  -- see LICENSE file
------------------------------------------------------------

-- test salsa20.lua

local salsa20 = require "plc.salsa20"
local bin = require "plc.bin"

local function test_salsa20_encrypt_decrypt()
	-- Check we can decrypt what we encrypted.
	local plain =
		"Ladies and Gentlemen of the class of '99: If I could "
	..	"offer you only one tip for the future, sunscreen would be it."
	local key =
		"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
	..	"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
	local nonce = "\x00\x00\x00\x4a\x00\x02\x00\x00"
	assert(#key == salsa20.key_size)
	assert(#nonce == salsa20.nonce_size)
	local counter = 1
	local et = salsa20.encrypt(key, counter, nonce, plain)
	assert(plain == salsa20.encrypt(key, counter, nonce, et))
	-- 
	-- test some input lengths
	for i = 1, 66 do
		plain = ('p'):rep(i)
		et = salsa20.encrypt(key, counter, nonce, plain)
		local dt = salsa20.decrypt(key, counter, nonce, et)
		assert((#et == #plain) and (dt == plain))
	end
	--
	return true	
end

local function _test_salsa20_ecrypt(hex_key, hex_nonce, bytes, hex_expected)
	local key = bin.hextos(hex_key)
	local nonce = bin.hextos(hex_nonce)
	local expected = bin.hextos(hex_expected)
	assert(#key == salsa20.key_size)
	assert(#nonce == salsa20.nonce_size)
	assert(bytes % 64 == 0)
	local plain = string.rep("\0", bytes)
	local et = salsa20.encrypt(key, 0, nonce, plain)
	local digest = string.rep("\0", 64)
	for i = 0, bytes - 1, 64 do
		digest = bin.xor8(digest, et:sub(i+1, i+64))
	end
	assert(digest == expected)
end

local function test_salsa20_ecrypt_1_0()
	-- Test vector 0 from ECRYPT set 1.
	-- http://www.ecrypt.eu.org/stream/svn/viewcvs.cgi/ecrypt/trunk/submissions/salsa20/full/verified.test-vectors
	local key = [[
		80000000000000000000000000000000
		00000000000000000000000000000000
	]]
	local nonce = "0000000000000000"
	local bytes = 512
	local expected = [[
		50EC2485637DB19C6E795E9C73938280
		6F6DB320FE3D0444D56707D7B456457F
		3DB3E8D7065AF375A225A70951C8AB74
		4EC4D595E85225F08E2BC03FE1C42567
	]]
	_test_salsa20_ecrypt(key, nonce, bytes, expected)
end


local function test_salsa20_ecrypt_6_0()
	-- Test vector 0 from ECRYPT set 6.
	-- http://www.ecrypt.eu.org/stream/svn/viewcvs.cgi/ecrypt/trunk/submissions/salsa20/full/verified.test-vectors
	local key = [[
		0053A6F94C9FF24598EB3E91E4378ADD
		3083D6297CCF2275C81B6EC11467BA0D
	]]
	local nonce = "0D74DB42A91077DE"
	local bytes = 131072
	local expected = [[
		C349B6A51A3EC9B712EAED3F90D8BCEE
		69B7628645F251A996F55260C62EF31F
		D6C6B0AEA94E136C9D984AD2DF3578F7
		8E457527B03A0450580DD874F63B1AB9
	]]
	_test_salsa20_ecrypt(key, nonce, bytes, expected)
end

local function test_hsalsa20()
	-- libsodium core2 test
	local key = bin.hextos [[
		1B27556473E985D462CD51197A9A46C7
		6009549EAC6474F206C4EE0844F68389
	]]
	local nonce = bin.hextos("69696EE955B62B73")
	local counter = string.unpack("<I8", (bin.hextos("CD62BDA875FC73D6")))
	local expected = bin.hextos [[
		DC908DDA0B9344A953629B7338207788
		80F3CEB421BB61B91CBD4C3E66256CE4
	]]
	local key2 = salsa20.hsalsa20(key, counter, nonce)
	assert(key2 == expected)
end

test_salsa20_encrypt_decrypt()
test_salsa20_ecrypt_1_0()
test_salsa20_ecrypt_6_0()
test_hsalsa20()

print("test_salsa20: ok")

