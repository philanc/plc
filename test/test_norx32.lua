-- Copyright (c) 2017 Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------
-- norx tests

local norx = require "plc.norx32"

local char = string.char
local concat = table.concat

local bin = require "plc.bin"  -- for hex conversion
local hextos = bin.hextos


------------------------------------------------------------------------

local function test_norx32()
	-- test vector from the specification at https://norx.io/data/norx.pdf
	-- (norx here is the NORX 32-4-1 variant)
	local t
	-- key: 00 01 02 ... 0F  (16 bytes)
	t = {}; for i = 1, 16 do t[i] = char(i-1) end;
	local key = concat(t)
	-- nonce: 20 21 22 ... 2F  (16 bytes)
	t = {}; for i = 1, 16 do t[i] = char(i+32-1) end;
	local nonce = concat(t)
	-- plain text, header, trailer: 00 01 02 ... 7F (128 bytes)
	t = {}; for i = 1, 128 do t[i] = char(i-1) end;
	local plain = concat(t)
	local header, trailer = plain, plain
	local crypted = norx.aead_encrypt(key, nonce, plain, header, trailer)
	-- print'---encrypted'; print(stohex(crypted, 16))
	local authtag = crypted:sub(#crypted-16+1)
	assert(authtag == hextos"D5 54 E4 BC 6B 5B B7 89 54 77 59 EA CD FF CF 47")
	local p = assert(norx.aead_decrypt(key, nonce, crypted, header, trailer))
	--print'---plain'; print(stohex(p, 16))
	assert(#crypted == #plain + 16)
	assert(p == plain)
	--
	-- test proper block handling and padding  for various input sizes
	for i = 1, 66 do 
		plain = ('p'):rep(i)
		crypted = norx.aead_encrypt(key, nonce, plain)
		assert(#crypted == #plain + 16)		
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
			assert(#crypted == #plain + 16)		
			assert(norx.aead_decrypt(key, nonce, crypted, a, z) == plain)
		end
	end
	--
end --test_norx32()


test_norx32()

print("test_norx32: ok")
