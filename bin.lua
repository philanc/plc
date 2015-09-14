-- Copyright (c) 2015  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------
-- misc binary data utilities: 
--	display hex data
--  convert to/from u32 arrays
--	xor binary strings

-- WARNING: API IS GOING TO CHANGE (A LOT!) :-)


local spack, sunpack = string.pack, string.unpack
local byte, char, concat = string.byte, string.char, table.concat
local strf = string.format

local function hex16(s, sep, prefix)
	sep = sep or " " -- optional separator between each byte
	prefix = prefix or "" -- optional prefix at beginning of each line
	local linesep = "\n" .. prefix
	local t = list()
	t:app(prefix)
	for i = 1, #s - 1 do
		t:app(strf("%02x", s:byte(i)))
		t:app((i%16 == 0) and linesep or sep) 
	end
	-- last byte, without any sep appended
	t:app(strf("%02x", s:byte(#s)))
	return t:join("")
end


local function p16(msg, s, sep, prefix) 
	print(msg); print(hex16(s, sep, prefix)) 
end

local function hexbb32(bb, sep, prefix)
	sep = sep or " " -- optional separator between each word
	prefix = prefix or "" -- optional prefix at beginning of each line
	local linesep = "\n" .. prefix
	local t = list()
	t:app(prefix)
	for i = 1,#bb do
		t:app(strf("%08x", bb[i]))
		t:app((i%4 == 0) and linesep or sep)
	end
	return t:join("")
end

local function pbb32(msg, s, sep, prefix) 
	print(msg); print(hexbb32(s, sep, prefix)) 
end

local function stobb32(s, pad)
	-- string -> bb32: array of u32 (little endian)
	-- pad (optional): add null bytes at end of block to ensure
	--   that the number of bytes in array is a multiple of pad
	--   eg. stobb32(s, 16) to have complete 16-byte blocks
	--   pad must be a multiple of 4.
	-- upon return, bb32.unused = total number of padding bytes added
	-- ie. after execution: #s + bb32.unused = #bb32 * 4
	local bb = {}
	local j = 1
	local lbn = #s % 4 --remaining bytes beyond the last full word
	local wn = #s // 4 --number of full words 
	for i = 1, wn do
		bb[i], j = sunpack('<I4', s, j)
	end
	-- process last bytes if any
	if lbn > 0 then
		local es = string.sub(s, j)
		for i = lbn, 4 do es = es .. '\0' end
		wn = wn + 1
		bb[wn] = sunpack('<I4', es)
		bb.unused = 4 - lbn
	else
		bb.unused = 0
	end
--~ 	print('stobb', #s, bb.unused, #bb)
	assert( #s + bb.unused == #bb * 4 )
	return bb
end

local function bb32pad(bb, bytepad)
	-- add null words at end of the bb array to ensure
	--   that the total number of bytes in array is a multiple of pad.
	--   eg. bb32pad(bb, 16) to have complete 16-byte blocks.
	--   pad must be a multiple of 4.
	-- pad if necessary
	local wn = #bb
	local wpad = bytepad // 4 
	rwn = wn % wpad
	if rwn > 0 then 
		for i = 1, wpad - rwn do
			bb[wn + i] = 0
			bb.unused = bb.unused + 4
		end
	end
	return bb
end --bb32pad

local function bb32tos(bb)
	-- bb -> string
	-- assume bb has been created by stobb32
	-- the last bb.unused bytes in bb are not included in string
	--  => #s == #bb * 4 - bb.unused)
	local u
	local t = {}
	local lfi = #bb - (bb.unused // 4) -- index of last full word
	for i = 1, lfi do
		t[i] = spack('<I4', bb[i])
	end
	-- rbn = number of bytes in the last non-full word, if any
	local rbn = 4 - bb.unused % 4  
	rbn = (rbn == 4) and 0 or rbn
--~ 	print(222, rbn)
	-- process these last bytes
	if rbn > 0 then
		-- this works because words are packed as little endian
		t[lfi] = string.sub(t[lfi], 1, rbn) 
	end
	local s = table.concat(t)
--~ 	print('bbtos', #s, bb.unused, #bb)
	assert( #s == #bb * 4 - bb.unused )
	return s
end

local function xor1(key, plain)
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
	-- build result one 64-byte block at a time
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
	hex16 = hex16,
	hexbb32 = hexbb32,
	p16 = p16,
	pbb32 = pbb32,
	stobb32 = stobb32,
	bb32tos = bb32tos,
	bb32pad = bb32pad,
	xor1 = xor1,
	xor64 = xor64,
	}
