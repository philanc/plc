-- Copyright (c) 2017 Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------
-- norx tests

local norx = require "plc.norx"

local char = string.char
local concat = table.concat

local bin = require "plc.bin"  -- for hex conversion
local hextos = bin.hextos


------------------------------------------------------------------------

local function test_norx()
	-- test vector from the specification at https://norx.io/data/norx.pdf
	-- (norx here is the default NORX 64-4-1 variant)
	local t
	-- key: 00 01 02 ... 1F  (32 bytes)
	t = {}; for i = 1, 32 do t[i] = char(i-1) end;
	local key = concat(t)
	-- nonce: 30 31 32 ... 4F  (32 bytes)
	t = {}; for i = 1, 32 do t[i] = char(i+32-1) end;
	local nonce = concat(t)
	-- plain text, header, trailer: 00 01 02 ... 7F (128 bytes)
	t = {}; for i = 1, 128 do t[i] = char(i-1) end;
	local plain = concat(t)
	local header, trailer = plain, plain
	local crypted = norx.aead_encrypt(key, nonce, plain, header, trailer)
	local authtag = crypted:sub(#crypted-32+1) -- 32 last bytes
	assert(authtag == hextos [[
		D1 F2 FA 33 05 A3 23 76 E2 3A 61 D1 C9 89 30 3F
		BF BD 93 5A A5 5B 17 E4 E7 25 47 33 C4 73 40 8E
		]])
	local p = assert(norx.aead_decrypt(key, nonce, crypted, header, trailer))
	--print'---plain'; print(stohex(p, 16))
	assert(#crypted == #plain + 32)
	assert(p == plain)
	--
	-- test proper block handling and padding  for various input sizes
	for i = 1, 66 do 
		plain = ('p'):rep(i)
		crypted = norx.aead_encrypt(key, nonce, plain)
		assert(#crypted == #plain + 32)		
		assert(norx.aead_decrypt(key, nonce, crypted) == plain)
	end
	--
	-- test against AD handling issues
	plain = ('p'):rep(65)
	for i = 1, 9 do
		a = ('A'):rep(i) -- AD prefix
		for j = 1, 9 do
			z = ('Z'):rep(i) -- AD suffix
			crypted = norx.aead_encrypt(key, nonce, plain, a, z)
			assert(#crypted == #plain + 32)		
			assert(norx.aead_decrypt(key, nonce, crypted, a, z) == plain)
		end
	end
	--
end --test_norx()


test_norx()

print("test_norx: ok")
