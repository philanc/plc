-- Copyright (c) 2018  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------
--[[
	
!!!               WORK IN PROGRESS                 !!!  
!!!  Only the permutation is exposed at the moment !!!

Gimli - Authenticated encryption and hash based on a sponge construction over the Gimli permutation by Dan Bernstein et al. (2017)
- see Gimli links and authors list at https://gimli.cr.yp.to/

The encryption and hash functions should be the same as the gimli functions 
in the luazen C crypto library - https://github.com/philanc/luazen
	gimli_encrypt, gimli_decrypt and gimli_hash

Encryption: 
32-byte keys (256 bits) and 16-byte nonces (128 bits)

Hash: 


]]

------------------------------------------------------------------------
-- local definitions

local spack, sunpack = string.pack, string.unpack
local byte, char = string.byte, string.char
local insert, concat = table.insert, table.concat

-- display the permutation state (an array of 12 32-byte integers)
--~ local function px12(st) 
--~ 	local fmt = "%08x %08x %08x %08x \n"
--~ 		.. "%08x %08x %08x %08x \n"
--~ 		.. "%08x %08x %08x %08x "
--~ 	print(string.format(fmt, 
--~ 		st[1], st[2], st[3], st[4],
--~ 		st[5], st[6], st[7], st[8],
--~ 		st[9], st[10], st[11], st[12]))
--~ end

------------------------------------------------------------------------
-- the gimli core permutation

local function rotate(x, n) 
    return ((x << n) | (x >> (32-n))) & 0xffffffff
end

local function gimli_core32(st)
	local x, y, z
	for round = 24, 1, -1 do
		for col = 1, 4 do
			x = rotate(st[col], 24)
			y = rotate(st[col+4], 9)
			z = st[col+8]
			st[col+8] = (x ~ (z << 1) ~ ((y & z) << 2)) & 0xffffffff
			st[col+4] = (y ~ x        ~ ((x | z) << 1)) & 0xffffffff
			st[col]   = (z ~ y        ~ ((x & y) << 3)) & 0xffffffff
		end--for
		-- !! 1-indexed arrays !! st[i] in C is st[i+1] in Lua
		if (round & 3) == 0 then
			-- // small swap: pattern s...s...s... etc.
			x = st[1]
			st[1] = st[2]
			st[2] = x
			x = st[3]
			st[3] = st[4]
			st[4] = x
		end
		if (round & 3) == 2 then
			-- // big swap: pattern ..S...S...S. etc.
			x = st[1]
			st[1] = st[3]
			st[3] = x
			x = st[2]
			st[2] = st[4]
			st[4] = x
		end
		if (round & 3) == 0 then
			-- // add constant: pattern c...c...c... etc.
			st[1] = st[1] ~ (0x9e377900 | round)
		end
--~ 		px12(st)
--~ 		print("^^ ----------------------", round)
	end--for rounds

end--gimli_core32()
------------------------------------------------------------------------

local st = {}  -- reuse the gimli state table

-- sponge construction over Gimli
-- Rate=16, Capacity=32. currently encryption is in overwrite mode, 
-- ie. input replaces R instead of XOR)


local function gimli_encrypt(k, n, m, prefix)
	-- encrypt string m, return a string c = prefix .. mac .. e
	-- where e is the encrypted message, mac is a 16-byte 
	-- authentication tag, and prefix is an optional string 
	-- (defaults to "") prepended to the result. 
	-- So #c == #prefix + 16 + #m
	-- k is the key as a 32-byte string
	-- n is the nonce as a 16-byte string
	
	--
end

local function gimli_decrypt(k, n, c, prefixln)
	-- decrypt string c
	-- return the decrypted string m or (nil, error msg) in case
	-- of error or if the MAC doesn't match
	-- prefixln is the optional length of a prefix (defaults to 0)
	-- #m = #c -16 - prefixln
	--
	--
end

local function gimli_hash(s, hashsize)
	-- return the hash of string s as a binary string
	-- hashsize is the optional size of the required hash 
	-- in bytes. hashsize defaults to 16
end

------------------------------------------------------------------------
-- the gimli module
return {
	-- the core permutation is exposed to facilitate tests and allow 
	-- arbitrary constructions by module user.
	gimli_core32 = gimli_core32,
	--
	gimli_encrypt = gimli_encrypt,
	gimli_decrypt = gimli_decrypt,
	gimli_hash = gimli_hash,
	--
}
