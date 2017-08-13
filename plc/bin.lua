-- Copyright (c) 2015  Phil Leblanc  -- see LICENSE file
------------------------------------------------------------------------
--[[

bin: misc binary data utilities:

stohex  - encode a string as a hex string
hextos 	- decode a hex string

rotr32	- rotate right the 32 lower bits of an integer (int64)
rotl32	- rotate left the 32 lower bits of an integer

xor1	- xor a string with a key (repeated as needed)
xor64	- same as xor1, but more efficient, memory-wise
xor8	- same, but assume #key is a multiple of 8 (more efficient)


]]
------------------------------------------------------------------------
-- some local definitions

local strf = string.format
local byte, char = string.byte, string.char
local spack, sunpack = string.pack, string.unpack

local app, concat = table.insert, table.concat

------------------------------------------------------------------------

local function stohex(s, ln, sep)
	-- stohex(s [, ln [, sep]])
	-- return the hex encoding of string s
	-- ln: (optional) a newline is inserted after 'ln' bytes
	--	ie. after 2*ln hex digits. Defaults to no newlines.
	-- sep: (optional) separator between bytes in the encoded string
	--	defaults to nothing (if ln is nil, sep is ignored)
	-- example:
	--	stohex('abcdef', 4, ":") => '61:62:63:64\n65:66'
	--	stohex('abcdef') => '616263646566'
	--
	if #s == 0 then return "" end
	if not ln then -- no newline, no separator: do it the fast way!
		return (s:gsub('.',
			function(c) return strf('%02x', byte(c)) end
			))
	end
	sep = sep or "" -- optional separator between each byte
	local t = {}
	for i = 1, #s - 1 do
		t[#t + 1] = strf("%02x%s", s:byte(i),
				(i % ln == 0) and '\n' or sep)
	end
	-- last byte, without any sep appended
	t[#t + 1] = strf("%02x", s:byte(#s))
	return concat(t)
end --stohex()

local function hextos(hs, unsafe)
	-- decode an hex encoded string. return the decoded string
	-- if optional parameter unsafe is defined, assume the hex
	-- string is well formed (no checks, no whitespace removal).
	-- Default is to remove white spaces (incl newlines)
	-- and check that the hex string is well formed
	local tonumber = tonumber
	if not unsafe then
		hs = string.gsub(hs, "%s+", "") -- remove whitespaces
		if string.find(hs, '[^0-9A-Za-z]') or #hs % 2 ~= 0 then
			error("invalid hex string")
		end
	end
	return hs:gsub(	'(%x%x)',
		function(c) return char(tonumber(c, 16)) end
		)
end -- hextos

local function rotr32(i, n)
	-- rotate right on 32 bits
	return ((i >> n) | (i << (32 - n))) & 0xffffffff
end

local function rotl32(i, n)
	-- rotate left on 32 bits
	return ((i << n) | (i >> (32 - n))) & 0xffffffff
end




local function xor1(key, plain)
	-- return a string which is a xor of plain and key
	-- plain and key may have arbitrary length.
	-- the result has the same length as plain.
	-- naive implementation, one byte at a time (ok for small strings)
	local ot = {}
	local ki, kln = 1, #key
	for i = 1, #plain do
		ot[#ot + 1] = char(byte(plain, i) ~ byte(key, ki))
		ki = ki + 1
		if ki > kln then ki = 1 end
	end
	return concat(ot)
end --xor1

local function xor8(key, plain)
	-- return a string which is a xor of plain and key
	-- plain may have arbitrary length.
	-- ** key length (in bytes) must be a multiple of 8 **
	-- the result has the same length as plain.
	-- (result is computed one uint64 at a time)
	assert(#key % 8 == 0, 'key not a multiple of 8 bytes')
	local ka = {} -- key as an array of uint64
	for i = 1, #key, 8 do
		-- !!beware below: () around sunpack are needed:
		-- app aka table.insert takes optionally 3 args
		-- and sunpack returns 2 args...
		app(ka, (sunpack("<I8", key, i)))
	end
	local kaln = #ka
	local rbn = #plain -- remaining bytes in plain
	local kai = 1  -- index in ka
	local ot = {}  -- table to collect output
	local ibu	-- an input block, as a uint64
	local ob	-- an output block as a string
	for i = 1, #plain, 8 do
		if rbn < 8 then
			local buffer = string.sub(plain, i) .. string.rep('\0', 8 - rbn)
			ibu = sunpack("<I8", buffer)
			ob = string.sub(spack("<I8", ibu ~ ka[kai]), 1, rbn)
		else
			ibu = sunpack("<I8", plain, i)
			ob = spack("<I8", ibu ~ ka[kai])
			rbn = rbn - 8
			kai = (kai < kaln) and (kai + 1) or 1
		end
		app(ot, ob)
	end
	return concat(ot)
end --xor8

------------------------------------------------------------------------
return  { -- bin module
	stohex = stohex,
	hextos = hextos,
	--
	rotr32 = rotr32,
	rotl32 = rotl32,
	--
	xor1 = xor1,
	xor8 = xor8,
	--
	}
