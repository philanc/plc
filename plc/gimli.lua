-- Copyright (c) 2018  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------
--[[
	
!!!               WORK IN PROGRESS                 !!!  
!!!  Only the permutation is exposed at the moment !!!

Gimli - Authenticated encryption and hash functions 
based on the Gimli permutation by Dan Bernstein et al.,
2017, https://gimli.cr.yp.to/



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

local st = {}  -- reuse the gimli state table

------------------------------------------------------------------------
-- the gimli module

return {
	-- the core permutation is exposed to facilitate tests and allow 
	-- arbitrary constructions by module user.
	gimli_core32 = gimli_core32,
	
}
