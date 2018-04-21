-- Copyright (c) 2018  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------
--[[
	
!!!               WORK IN PROGRESS                 !!!  
!!!  Only the permutation is exposed at the moment !!!

The Gimli permutation by Dan Bernstein et al. (2017)
- see Gimli links and authors list at https://gimli.cr.yp.to/

Note: The performance of this Lua implementation has been disappointing:

   To encrypt a 10 Mbyte string, with a 16-byte block, the number of 
   permutations is approximately 10 * 1024 * 1024 / 16. 

   On an average laptop - CPU i5 M430 @ 2.27 GHz, Linux 4.4 x86_64, 
   Lua 5.3.4, the elapsed time for these permutations is:
   -- gimli_core32:       42-43s   -- direct implementation
   -- gimli_core32opt:    20-21s   -- Lua-optimized version

The times for complete encryption would be higher. Which makes a
pure Lua gimli-based encryption not competitive with established 
algorithms such as Salsa20 or Chacha20 (7-8s on the same laptop)

Given the performance, the encryption and hash functions have 
not been implemented.


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
	-- this is the default implementation, based on the C reference code
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



local function gimli_core32opt(st)
	-- core permutation optimized for Lua
	-- state copied to local variables for the state, 
	-- the "for col..." loop is unrolled
	-- rotates are inlined
	-- the unneeded 32-clamp after rotate ("& 0xffffffff") is removed

	local x, y, z
	local st1, st2, st3, st4, st5, st6, st7, st8, st9, st10, st11, st12 = 
		st[1],st[2],st[3],st[4],st[5],st[6],
		st[7],st[8],st[9],st[10],st[11],st[12]
	
	for round = 24, 1, -1 do
		--unroll "for col..."
--~ 		for col = 1, 4 do
--~ 			x = rotate(st[col], 24)
--~ 			y = rotate(st[col+4], 9)
--~ 			z = st[col+8]
--~ 			st[col+8] = (x ~ (z << 1) ~ ((y & z) << 2)) & 0xffffffff
--~ 			st[col+4] = (y ~ x        ~ ((x | z) << 1)) & 0xffffffff
--~ 			st[col]   = (z ~ y        ~ ((x & y) << 3)) & 0xffffffff
		--col=1
--~ 		x = rotate(st1, 24)
--~ 		y = rotate(st5, 9)
		x = ((st1 << 24) | (st1 >> (8))) --& 0xffffffff
		y = ((st5 << 9) | (st5 >> (23))) --& 0xffffffff
		z = st9
		st9 = (x ~ (z << 1) ~ ((y & z) << 2)) & 0xffffffff
		st5 = (y ~ x        ~ ((x | z) << 1)) & 0xffffffff
		st1   = (z ~ y        ~ ((x & y) << 3)) & 0xffffffff
		--col=2
--~ 		x = rotate(st2, 24)
--~ 		y = rotate(st6, 9)
		x = ((st2 << 24) | (st2 >> (8))) --& 0xffffffff
		y = ((st6 << 9) | (st6 >> (23))) --& 0xffffffff
		z = st10
		st10 = (x ~ (z << 1) ~ ((y & z) << 2)) & 0xffffffff
		st6 = (y ~ x        ~ ((x | z) << 1)) & 0xffffffff
		st2   = (z ~ y        ~ ((x & y) << 3)) & 0xffffffff
		--col=3
--~ 		x = rotate(st3, 24)
--~ 		y = rotate(st7, 9)
		x = ((st3 << 24) | (st3 >> (8))) --& 0xffffffff
		y = ((st7 << 9) | (st7 >> (23))) --& 0xffffffff
		z = st11
		st11 = (x ~ (z << 1) ~ ((y & z) << 2)) & 0xffffffff
		st7 = (y ~ x        ~ ((x | z) << 1)) & 0xffffffff
		st3   = (z ~ y        ~ ((x & y) << 3)) & 0xffffffff
		--col=4
--~ 		x = rotate(st4, 24)
--~ 		y = rotate(st8, 9)
		x = ((st4 << 24) | (st4 >> (8))) --& 0xffffffff
		y = ((st8 << 9) | (st8 >> (23))) --& 0xffffffff
		z = st12
		st12 = (x ~ (z << 1) ~ ((y & z) << 2)) & 0xffffffff
		st8 = (y ~ x        ~ ((x | z) << 1)) & 0xffffffff
		st4   = (z ~ y        ~ ((x & y) << 3)) & 0xffffffff
--~ 		end--for unrolled
		-- !! 1-indexed arrays !! st[i] in C is st[i+1] in Lua
		if (round & 3) == 0 then
			-- // small swap: pattern s...s...s... etc.
			x = st1
			st1 = st2
			st2 = x
			x = st3
			st3 = st4
			st4 = x
		end
		if (round & 3) == 2 then
			-- // big swap: pattern ..S...S...S. etc.
			x = st1
			st1 = st3
			st3 = x
			x = st2
			st2 = st4
			st4 = x
		end
		if (round & 3) == 0 then
			-- // add constant: pattern c...c...c... etc.
			st1 = st1 ~ (0x9e377900 | round)
		end
--~ 		px12(st)
--~ 		print("^^ ----------------------", round)
	end--for rounds
	st[1],st[2],st[3],st[4],st[5],st[6],st[7],st[8],st[9],st[10],st[11],st[12]
	= st1, st2, st3, st4, st5, st6, st7, st8, st9, st10, st11, st12
	
end--gimli_core32opt()

------------------------------------------------------------------------
-- the gimli module
return {
	-- the core permutation is exposed to facilitate tests and allow 
	-- arbitrary constructions by module user.
	gimli_core32 = gimli_core32,
	gimli_core32opt = gimli_core32opt,
	--
--~ 	gimli_encrypt = gimli_encrypt,
--~ 	gimli_decrypt = gimli_decrypt,
--~ 	gimli_hash = gimli_hash,
	--
}
