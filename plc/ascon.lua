-- Copyright (c) 2023  Phil Leblanc  -- see LICENSE file
------------------------------------------------------------------------
--[[
      !!  WORK IN PROGRESS  !!  DON'T USE IT  !!

Ascon encryption, hash and MAC functions
This implements the Ascon128 variant.


]]


local spack, sunpack = string.pack, string.unpack
local insert = table.insert
local strf = string.format

local function pix(x) print(strf("%016x", x)) end

-- from api.h
local CRYPTO_BYTES = 32
local ASCON_HASH_BYTES = 32
local ASCON_XOF_BYTES = 0     -- named ASCON_HASH_BYTES in ref/xof
local ASCON_HASH_ROUNDS = 12

-- from constants.h
--- [ compute the constants in *each directory* ... ]
local ASCON_HASH_RATE = 8
local ASCON_HASH_IV = 0x00400c0000000100
local ASCON_XOF_IV =  0x00400c0000000000
local ASCON_PRF_IV = 0x80808c0000000000
local ASCON_MAC_IV = 0x80808c0000000080


local s0, s1, s2, s3, s4  -- ascon state - 5 * uint64

local function ROR(x, n)
	return (x >> n) | (x << (-n & 63))
end

local function ROUND(C)
	local t0, t1, t2, t3, t4 -- the internal t state
	-- addition of round constant
	s2 = s2 ~ C
	-- substitution layer
	s0 = s0 ~ s4
	s4 = s4 ~ s3
	s2 = s2 ~ s1
	-- start of keccak s-box
	t0 = s0 ~ ((~ s1) & s2)
	t1 = s1 ~ ((~ s2) & s3)
	t2 = s2 ~ ((~ s3) & s4)
	t3 = s3 ~ ((~ s4) & s0)
	t4 = s4 ~ ((~ s0) & s1)
	-- end of keccak s-box
	t1 = t1 ~ t0
	t0 = t0 ~ t4
	t3 = t3 ~ t2
	t2 = ~t2

	-- linear diffusion layer
	s0 = t0 ~ ROR(t0, 19) ~ ROR(t0, 28)
	s1 = t1 ~ ROR(t1, 61) ~ ROR(t1, 39)
	s2 = t2 ~ ROR(t2, 1) ~ ROR(t2, 6)
	s3 = t3 ~ ROR(t3, 10) ~ ROR(t3, 17)
	s4 = t4 ~ ROR(t4, 7) ~ ROR(t4, 41)
end--ROUND

local function P12()  -- the ascon128 permutation
	ROUND(0xf0)
--~ print(s0, s1, s2, s3, s4)
	ROUND(0xe1)
	ROUND(0xd2)
	ROUND(0xc3)
	ROUND(0xb4)
	ROUND(0xa5)
	ROUND(0x96)
	ROUND(0x87)
	ROUND(0x78)
	ROUND(0x69)
	ROUND(0x5a)
	ROUND(0x4b)
end--P12

local function hash(str, xoflen)
	-- str: the string to hash
	-- xoflen: the hash length. 
	--	if not nil, function is xof
	--	if nil, function is regular hash. hash length is 32
	
	-- initialize state
	s0 = xoflen and ASCON_XOF_IV or ASCON_HASH_IV
	s1, s2, s3, s4 = 0, 0, 0, 0
	P12()
	
	-- absorb full plaintext blocks
	local len = #str
	local i = 1  -- index of current block in input string str
	local x
	while len >= ASCON_HASH_RATE do
		-- get 8 bytes as a big-endian uint64
		x, i = sunpack(">I8", str, i) 
		s0 = s0 ~ x
		P12()
		len = len - ASCON_HASH_RATE
	end
	
	-- absorb final plaintext block 
	local lastblock = str:sub(i)
	-- pad the last block. 
	-- ensure there are enough zero bytes after the padding byte
	lastblock = lastblock .. "\x80\0\0\0\0\0\0\0\0"
	x = sunpack(">I8", lastblock)
	s0 = s0 ~ x
	P12()
	
	-- squeeze full output blocks
	local t = {}  -- will contain blocks of the hash/xof digest
	if xoflen then len = xoflen else len = ASCON_HASH_BYTES end
	while len > ASCON_HASH_RATE do 
		x = spack(">I8", s0)
		insert(t, x)
		P12()
		len = len - ASCON_HASH_RATE
	end
		
	-- squeeze final output block
	x = spack(">I8", s0)
	x = x:sub(1, len)
	insert(t, x)
	
	-- return the digest as a binary string
	x = table.concat(t, "")
	return x
end--hash

local function prf_or_mac(iv, k, str, outlen)
	-- internal function. Use either mac() or prf()
	--   which are defined after this function
	-- compute either mac or prf according to 
	-- the IV used to initialize the state
	assert(#k == 16, "key length error. must be 16.")
	local K0 = sunpack(">I8", k, 1)
	local K1 = sunpack(">I8", k, 9)
	-- initialize
	s0 = iv
	s1 = K0
	s2 = K1
	s3 = 0
	s4 = 0
	P12()

	-- absorb full plaintext blocks
	local inlen = #str
	local ix = 1  -- index of current block in input string str
	local x
	local i
	
	-- prf absorbs 32-byte blocks, ie 4 8-byte blocks at a time
	while inlen >= 32 do
		-- get 8 bytes as a big-endian uint64
		x, ix = sunpack(">I8", str, ix) 
		s0 = s0 ~ x
		x, ix = sunpack(">I8", str, ix) 
		s1 = s1 ~ x
		x, ix = sunpack(">I8", str, ix) 
		s2 = s2 ~ x
		x, ix = sunpack(">I8", str, ix) 
		s3 = s3 ~ x
		P12()
		len = len - 32
	end
	
	-- absorb last block
	lastblock = str:sub(ix) 
print("lastblock#", #lastblock)
	-- pad the last block
	-- ensure there are enough zero bytes after the padding byte
	-- (the block must be at least 32-byte long
	lastblock = lastblock .. "\x80" .. string.rep("\0", 32)
	ix = 1 -- index in lastblock
	x, ix = sunpack(">I8", lastblock, ix) 
	s0 = s0 ~ x
	x, ix = sunpack(">I8", lastblock, ix) 
	s1 = s1 ~ x
	x, ix = sunpack(">I8", lastblock, ix) 
	s2 = s2 ~ x
	x, ix = sunpack(">I8", lastblock, ix) 
	s3 = s3 ~ x
	--domain separation
	s4 = s4 ~ 1
	P12()
	
	-- sqeeze output
	local len = outlen
	local t = {}
	while len > 0 do
		x = spack(">I8", s0)
		insert(t, x)
		x = spack(">I8", s1)
		insert(t, x)
		len = len - 16
		P12()
	end
	local tag = table.concat(t, "")
	tag = tag:sub(1, outlen) -- trim tag to the desired length
	return tag
end--prf_or_mac

local function prf(k, str, outlen)
	return prf_or_mac(ASCON_PRF_IV, k, str, outlen or 16)
end

local function mac(k, str)
	return prf_or_mac(ASCON_MAC_IV, k, str, 16)
end

------------------------------------------------------------------------
-- the ascon module

return {
	hash = hash,
	mac = mac,
	prf = prf,

}

he = require"he"
s2x = he.stohex

h = mac("abcdefghijklmnop", "ascon")
print('prf/mac', #h, s2x(h))
h = prf("abcdefghijklmnop", "ascon")
print('prf/mac', #h, s2x(h))
h = prf("abcdefghijklmnop", "ascon", 23)
print('prf/mac', #h, s2x(h))

