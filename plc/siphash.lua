-- Copyright (c) 2017  Phil Leblanc  -- see LICENSE file
------------------------------------------------------------------------


--[[

=== siphash

See https://131002.net/siphash/

"SipHash is a family of pseudorandom functions (a.k.a. keyed hash 
functions) optimized for speed on short messages. 

Target applications include network traffic authentication and 
defense against hash-flooding DoS attacks."

SipHash has been designed in 2012 by Jean-Philippe Aumasson 
and Daniel J. Bernstein.

--

The variant implemented here is the default SipHash-2-4, but can be easily 
turned into the more secure SipHash-4-8 (just change the constants cROUNDS
and dROUNDS to respectively 4 and 8)



]]

local strf = string.format
local byte, char = string.byte, string.char
local spack, sunpack = string.pack, string.unpack
local app, concat = table.insert, table.concat
local function pf(...) print(string.format(...)) end

local function rotl(i, n)
	-- rotate left on 64 bits (rotate uint i by n positions)
	return (i << n) | (i >> (64 - n)) 
end


-- the default function is SipHash-2-4 
local cROUNDS = 2  -- number of compression rounds
local dROUNDS = 4  -- number of diffusion rounds

local function siphash_core(ins, k0, k1, flag16)
	-- k0, k1: 16-byte key as 2 integers
	-- return result as one (if flag16 is false) or two integers 
	local v0 = 0x736f6d6570736575
	local v1 = 0x646f72616e646f6d
	local v2 = 0x6c7967656e657261
	local v3 = 0x7465646279746573
	local inslen = #ins
	local left = inslen & 7
	local b = (#ins) << 56
	local ii = 1
	local m
	local function sipround(v0, v1, v2, v3)
		v0 = v0 + v1
		v1 = (v1 << 13) | (v1 >> 51) -- 64-13
		v1 = v1 ~ v0
		v0 = (v0 << 32) | (v0 >> 32) -- 64-32
		v2 = v2 + v3
		v3 = (v3 << 16) | (v3 >> 48) -- 64-16
		v3 = v3 ~ v2
		v0 = v0 + v3
		v3 = (v3 << 21) | (v3 >> 43) -- 64-21
		v3 = v3 ~ v0
		v2 = v2 + v1
		v1 = (v1 << 17) | (v1 >> 47) -- 64-17
		v1 = v1 ~ v2
		v2 = (v2 << 32) | (v2 >> 32) -- 64-32
		return v0, v1, v2, v3
	end
	--[[ (same output as the TRACE macro in the C reference implementation)
	local function trace()
		pf("(%d) v0 %08x %08x", inslen, v0>>32, v0 & 0xffffffff)
		pf("(%d) v1 %08x %08x", inslen, v1>>32, v1 & 0xffffffff)
		pf("(%d) v2 %08x %08x", inslen, v2>>32, v2 & 0xffffffff)
		pf("(%d) v3 %08x %08x", inslen, v3>>32, v3 & 0xffffffff)
	end
	--]]
    v3 = v3 ~ k1
    v2 = v2 ~ k0
    v1 = v1 ~ k1
    v0 = v0 ~ k0
	--trace()
	if flag16 then v1 = v1 ~ 0xee end
	while inslen - ii >= 7 do
		m, ii = sunpack("<I8", ins, ii)
		v3 = v3 ~ m
		--trace()
		for i = 1, cROUNDS do v0, v1, v2, v3 = sipround(v0, v1, v2, v3) end
		--trace()
		v0 = v0 ~ m
		--trace()
	end
	if left > 0 then b = b | (byte(ins, ii) ) end	
	if left > 1 then b = b | (byte(ins, ii+1) << 8) end	
	if left > 2 then b = b | (byte(ins, ii+2) << 16) end	
	if left > 3 then b = b | (byte(ins, ii+3) << 24) end	
	if left > 4 then b = b | (byte(ins, ii+4) << 32) end	
	if left > 5 then b = b | (byte(ins, ii+5) << 40) end	
	if left > 6 then b = b | (byte(ins, ii+6) << 48) end	
	v3 = v3 ~ b
	--trace()
	for i = 1, cROUNDS do v0, v1, v2, v3 = sipround(v0, v1, v2, v3) end
	v0 = v0 ~ b
	v2 = v2 ~ (flag16 and 0xee or 0xff)
	--trace()
	for i = 1, dROUNDS do v0, v1, v2, v3 = sipround(v0, v1, v2, v3) end
	
	local r1, r2
	r1 = v0 ~ v1 ~ v2 ~ v3
	if not flag16 then return r1, nil end
	v1 = v1 ~ 0xdd
	--trace()
	for i = 1, dROUNDS do v0, v1, v2, v3 = sipround(v0, v1, v2, v3) end
	r2 = v0 ~ v1 ~ v2 ~ v3
	return r1, r2
end--siphash_core()

local function siphash(ins, ks, flag16)
	-- return hash of string ins
	-- optional key is string ks (must be 16 bytes)
	-- if flag16, return a 16-byte hash string (binary - no hex encoding)
	-- else (default) return a 8-byte hash string
	ks = ks or
	"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
	local k0, k1 -- the MAC key as 2 8-byte integers
	if ks then 
		assert(#ks == 16, "key must be a 16-byte string")
		k0, k1 = sunpack("<I8I8", ks)
	else
		-- default key used in tests: [00, 01, 02, ... 0f]
		k0, k1 = 0x0706050403020100, 0x0f0e0d0c0b0a0908
	end
	local r1, r2 = siphash_core(ins, k0, k1, flag16)
	return flag16 and spack("<I8I8", r1, r2) or spack("<I8", r1) 
end

local function siphash16(ins, ks) return siphash(ins, ks, true) end

------------------------------------------------------------------------
return {
	siphash_core = siphash_core,
	siphash = siphash,
	siphash16 = siphash16,
}

