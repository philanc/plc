-- Copyright (c) 2015  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------
--[[

blake2b hash function -- See https://blake2.net/

Specified in RFC 7693, https://tools.ietf.org/html/rfc7693

BLAKE2 is based on the SHA-3 proposal BLAKE, designed by Jean-Philippe Aumasson,
Luca Henzen, Willi Meier, and Raphael C.-W. Phan.

This Lua 5.3 implementation is derived from the C reference code in RFC 7693.


]]

------------------------------------------------------------------------
-- local definitions


local sunpack = string.unpack
local concat = table.concat

------------------------------------------------------------------------

local function ROTR64(x, n)
    return (x >> n) | (x << (64-n))
end

-- G Mixing function.

local function G(v, a, b, c, d, x, y)
	v[a] = v[a] + v[b] + x
	v[d] = ROTR64(v[d] ~ v[a], 32)
	v[c] = v[c] + v[d]
	v[b] = ROTR64(v[b] ~ v[c], 24)
	v[a] = v[a] + v[b] + y
	v[d] = ROTR64(v[d] ~ v[a], 16)
	v[c] = v[c] + v[d]
	v[b] = ROTR64(v[b] ~ v[c], 63)
end

--  Initialization Vector.
local iv = {
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
}

local sigma = {
	-- array index start at 1 in Lua,
	-- => all the permutation values are incremented by one
	{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 },
	{ 15, 11, 5, 9, 10, 16, 14, 7, 2, 13, 1, 3, 12, 8, 6, 4 },
	{ 12, 9, 13, 1, 6, 3, 16, 14, 11, 15, 4, 7, 8, 2, 10, 5 },
	{ 8, 10, 4, 2, 14, 13, 12, 15, 3, 7, 6, 11, 5, 1, 16, 9 },
	{ 10, 1, 6, 8, 3, 5, 11, 16, 15, 2, 12, 13, 7, 9, 4, 14 },
	{ 3, 13, 7, 11, 1, 12, 9, 4, 5, 14, 8, 6, 16, 15, 2, 10 },
	{ 13, 6, 2, 16, 15, 14, 5, 11, 1, 8, 7, 4, 10, 3, 9, 12 },
	{ 14, 12, 8, 15, 13, 2, 4, 10, 6, 1, 16, 5, 9, 7, 3, 11 },
	{ 7, 16, 15, 10, 12, 4, 1, 9, 13, 3, 14, 8, 2, 5, 11, 6 },
	{ 11, 3, 9, 5, 8, 7, 2, 6, 16, 12, 10, 15, 4, 13, 14, 1 },
	{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 },
	{ 15, 11, 5, 9, 10, 16, 14, 7, 2, 13, 1, 3, 12, 8, 6, 4 }
}


local function compress(ctx, last)
	-- Compression function. "last" flag indicates last block.
	local v, m = {}, {} -- both v and m are u64[16]
	for i = 1, 8 do
		v[i] = ctx.h[i]
		v[i+8] = iv[i]
	end
	v[13] = v[13] ~ ctx.t[1]  -- low 64 bits of offset
	v[14] = v[14] ~ ctx.t[2]  -- high 64 bits
	if last then v[15] = ~v[15] end
	for i = 0, 15 do -- get little-endian words
		m[i+1] = sunpack("<I8", ctx.b, i*8+1) --copy b as a seq of u64
	end

	for i = 1, 12 do -- twelve rounds  --(beware 1-based indexing in Lua!)
		-- print("v for i=", i); p64(v)
		G(v, 1, 5, 9, 13, m[sigma[i][ 1]], m[sigma[i][ 2]])
		G(v, 2, 6,10, 14, m[sigma[i][ 3]], m[sigma[i][ 4]])
		G(v, 3, 7,11, 15, m[sigma[i][ 5]], m[sigma[i][ 6]])
		G(v, 4, 8,12, 16, m[sigma[i][ 7]], m[sigma[i][ 8]])
		G(v, 1, 6,11, 16, m[sigma[i][ 9]], m[sigma[i][10]])
		G(v, 2, 7,12, 13, m[sigma[i][11]], m[sigma[i][12]])
		G(v, 3, 8, 9, 14, m[sigma[i][13]], m[sigma[i][14]])
		G(v, 4, 5,10, 15, m[sigma[i][15]], m[sigma[i][16]])

	end--twelve rounds

	for i = 1, 8 do
		ctx.h[i] = ctx.h[i] ~ v[i] ~ v[i + 8]
	end
end--compress()

local update  -- (update is used in init() below, but defined after)

local function init(outlen, key)
	-- initialize the blake function
	-- 1 <= outlen <= 64 gives the digest size in bytes. defaults to 64
	-- key: optional secret key (also <= 64 bytes). defaults to no key
	-- return the initialized context
	outlen = outlen or 64
	key = key or ""
	local keylen = #key
	if outlen < 1 or outlen > 64 or (key and #key > 64) then
		return nil, "illegal parameters"
	end
	local ctx = {h={}, t={}, c=1, outlen=outlen} -- the blake2 context
	-- note: ctx.c is the index of 1st byte free in input buffer (ctx.b)
	-- it is not used in this implementation
	for i = 1, 8 do ctx.h[i] = iv[i] end  -- state, "param block"
	ctx.h[1] = ctx.h[1] ~ 0x01010000 ~ (keylen << 8) ~ outlen
	ctx.t[1] = 0   --input count low word
	ctx.t[2] = 0   --input count high word
	-- zero input block
	ctx.b = ""
	if keylen > 0 then
		update(ctx, key)
		-- ctx.c = 128 --  pad b with zero bytes
		ctx.b = ctx.b .. string.rep('\0', 128 - #ctx.b)
		assert(#ctx.b == 128)
	end
	return ctx
end --init()

update = function(ctx, data)
	-- buffer mgt cannot be done the C way..
	local bln, rln, iln
	local i = 1 -- index of 1st byte to process in data
	while true do
		bln = #ctx.b  -- current number of bytes in the input buffer
		assert(bln <= 128)
		if bln == 128 then --ctx.b is full; process it.
			-- add counters
			ctx.t[1] = ctx.t[1] + 128
			-- warning: this is a signed 64bit addition
			-- here it is assumed that the total input is less
			-- than 2^63 bytes (this should be enough for a
			-- pure Lua implementation!) => ctx.t[1] overflow is ignored.
			compress(ctx, false)   -- false means not last
			ctx.b = "" -- empty buffer
		else -- ctx.b is not full; append more bytes from data
			rln =  128 - bln  -- remaining space (in bytes) in ctx.b
			iln = #data - i + 1  -- number of bytes yet to process in data
			if iln < rln then
				ctx.b = ctx.b .. data:sub(i, i + iln -1)
				-- here, all data bytes have been processed or put in
				-- buffer and buffer is not full. we are done.
				break
			else
				ctx.b = ctx.b .. data:sub(i, i + rln -1)
				i = i + rln
			end
		end
	end--while
end --update()

local function final(ctx)
	-- finalize the hash and return the digest as a string
	--
	local bln = #ctx.b
	-- add number of remaining bytes in buffer (ignore carry overflow)
	ctx.t[1] = ctx.t[1] + bln
	-- pad the buffer with zero bytes
	local rln =  128 - bln  -- remaining space (in bytes) in ctx.b
	ctx.b = ctx.b .. string.rep('\0', rln)
	compress(ctx, true) -- true means final block
	-- extract the digest (outlen bytes long)
	local outtbl = {}
	for i = 0, ctx.outlen - 1 do
		outtbl[i+1] = string.char(
			(ctx.h[(i >> 3) + 1] >> (8 * (i & 7))) & 0xff)
	end
	local dig = concat(outtbl)
	return dig
end --final()

local function hash(data, outlen, key)
	-- convenience function
	-- return the hash of data as a string
	-- outlen is optional digest length (1..64) - defaults to 64
	-- key is an optional key string (length must be 1..64)
	local ctx, msg = init(outlen, key)
	if not ctx then return ctx, msg end
	update(ctx, data)
	return final(ctx)
end --hash


------------------------------------------------------------------------


return { --black2b module
	init = init,
	update = update,
	final = final,
	hash = hash,
}




