-- Copyright (c) 2015  Phil Leblanc  -- see LICENSE file
------------------------------------------------------------
--[[ 

bin: misc binary data utilities: 

stohex  - encode a string as a hex string
hextos 	- decode a hex string

rotr32	- rotate right the 32 lower bits of an integer (int64)
rotl32	- rotate left the 32 lower bits of an integer 

xor1	- xor a string with a key (repeated as needed)
xor64	- same as xor1, but more efficient, memory-wise



]]

local strf = string.format
local byte, char = string.byte, string.char
local concat = table.concat

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
	if not ln then -- no newline, no separator: do it the fast way!
		return s:gsub('.', 
			function(c) return strf('%02x', byte(c)) end
			)
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
		s = string.gsub(s, "%s+", "") -- remove whitespaces
		if string.find(hs, '[^0-9A-Za-z]') or hs % 2 ~= 0 then
			error("invalid hex string")
		end
	end
	return s:gsub(	'(%x%x)', 
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
	-- naive implementation, one byte at a time
	local t = {}
	local ki, kln = 1, #key
	for i = 1, #plain do
		ki = ki + 1
		if ki > kln then ki = 1 end
		t[#t + 1] = char(byte(plain, i) ~ byte(key, ki))
	end
	return table.concat(t)
end --xor1

local function xor64(key, plain)
	-- return a string which is a xor of plain and key
	-- functionnaly equivalent to xor1().
	-- result is built one 64-byte block at a time (more efficient, 
	-- especially memory-wise)
	local concat = table.concat
	local pln = #plain
	local lbbn = pln % 64 	--number of bytes in last block
				-- or 0 if last block is full
	local bn = pln // 64 -- number of blocks
	if lbbn > 0 then bn = bn + 1 end
	local b = {} -- 64-byte block - will be reused
	local t = {}
	local bi = 1 -- index in block
	local ki, kln = 1, #key -- key index and length
	for i = 1, pln do
		b[bi] = char(byte(plain, i) ~ byte(key, ki))
		ki = ki + 1
		if ki > kln then ki = 1 end
		bi = bi + 1
		if bi > 64 then
			bi = 1
			t[#t + 1] = concat(b)
		end
	end--for
	-- append bytes in last block if not full
	if lbbn > 0 then
		for i = lbbn+1, 64 do b[i] = nil end
		assert(#b == lbbn)
		t[#t + 1] = concat(b)
	end--if
	return concat(t)
end --xor64


return  { -- bin module
	stohex = stohex,
	hextos = hextos,
	--
	xor1 = xor1,
	xor64 = xor64,
	--
	}
