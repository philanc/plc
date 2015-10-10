-- Copyright (c) 2015  Phil Leblanc  -- see LICENSE file
------------------------------------------------------------------------
--[[ 		** WORK IN PROGRESS  --  CANNOT BE USED AS-IS **
					
XTEA block cipher

Designed by Roger Needham and David Wheeler in 1997

see Wikipedia page
https://en.wikipedia.org/wiki/XTEA

This implementation is based on the public domain C code included
on the Wikipedia page (modified to precompute the "sum + key[...]" terms)

]]

------------------------------------------------------------------------
-- debug functions (should be removed)

local bin = require"bin"
local stx = bin.stohex
local xts = bin.hextos
local function px(s) print(stx(s, 16, " ")) end
local function pf(...) print(string.format(...)) end
local function p8(b) print(string.format("%016x", b)) end

------------------------------------------------------------------------
-- local definitions

local spack, sunpack = string.pack, string.unpack
local app, concat = table.insert, table.concat

local function rotr32(i, n)
	-- rotate right on 32 bits
	return ((i >> n) | (i << (32 - n))) & 0xffffffff
end

local function rotl32(i, n)
	-- rotate left on 32 bits
	return ((i << n) | (i >> (32 - n))) & 0xffffffff
end

------------------------------------------------------------------------
local ROUNDS = 32

local function keysetup(key)
	-- key is a 16-byte string (128-bit key)
	-- precompute "sum + key[]"
	-- returns a "state" with both tables (2 * 32 * uint32)
	assert(#key == 16)
	local kt = table.pack(sunpack('>I4I4I4I4', key))
	local skt0 = {} -- the "sum + key[sum&3]" table (encrypt)
	local skt1 = {} -- the "sum + key[sum>>11 & 3]" table (encrypt)
	local sum, delta = 0, 0x9E3779B9
	for i = 1, ROUNDS do
		skt0[i] = sum + kt[(sum & 3) + 1]
		sum = (sum + delta) & 0xffffffff
		skt1[i] = sum + kt[((sum>>11) & 3) + 1]
	end
	return { skt0=skt0, skt1=skt1, }
end

local function encryptblock(st, b)
	-- st: state, produced by keysetup
	-- b: 64-bit block as a 8-byte string
	--
	local skt0, skt1 = st.skt0, st.skt1
	-- interpret b as two big endian uint32
	local v0, v1 = sunpack(">I4I4", b)
	local sum, delta = 0, 0x9E3779B9
	for i = 1, ROUNDS do
		v0 = (v0 + ((((v1<<4) ~ (v1>>5)) + v1) ~ skt0[i])) & 0xffffffff
		v1 = (v1 + ((((v0<<4) ~ (v0>>5)) + v0) ~ skt1[i])) & 0xffffffff
	end
	b = spack(">I4I4", v0, v1) -- big endian
	return b
end

local function encryptu64(st, b)
	-- st: state, produced by keysetup
	-- b: 64-bit block as a uint64 (big endian - unpack with ">I8")
	local skt0, skt1 = st.skt0, st.skt1
	-- xtea works on big endian numbers: v0 is MSB, v1 is LSB
	local v0, v1 = b >> 32, b & 0xffffffff
--~ 	p8(v0);p8(v1);p8(b)	
	local sum, delta = 0, 0x9E3779B9
	for i = 1, ROUNDS do
		v0 = (v0 + ((((v1<<4) ~ (v1>>5)) + v1) ~ skt0[i])) & 0xffffffff
		v1 = (v1 + ((((v0<<4) ~ (v0>>5)) + v0) ~ skt1[i])) & 0xffffffff
	end
	b = (v0 << 32) | v1
	return b
end

local function decryptblock(st, b)
	-- st: state, produced by keysetup
	-- b: 64-bit encrypted block as a 16-byte string
	-- returns decrypted block as a 16-byte string
	local skt0, skt1 = st.skt0, st.skt1
	local v0, v1 = sunpack(">I4I4", b)
	local sum, delta = 0, 0x9E3779B9
	for i = ROUNDS, 1, -1 do
		v1 = (v1 - ((((v0<<4) ~ (v0>>5)) + v0) ~ skt1[i])) & 0xffffffff
		v0 = (v0 - ((((v1<<4) ~ (v1>>5)) + v1) ~ skt0[i])) & 0xffffffff
	end
	b = spack(">I4I4", v0, v1) -- big endian
	return b
end

local function decryptu64(st, b)
	-- st: state, produced by keysetup
	-- b: 64-bit encrypted block as a uint64 (big endian)
	-- returns decrypted block as a uint64
	local skt0, skt1 = st.skt0, st.skt1
	local v0, v1 = b >> 32, b & 0xffffffff
	local sum, delta = 0, 0x9E3779B9
	for i = ROUNDS, 1, -1 do
		v1 = (v1 - ((((v0<<4) ~ (v0>>5)) + v0) ~ skt1[i])) & 0xffffffff
		v0 = (v0 - ((((v1<<4) ~ (v1>>5)) + v1) ~ skt0[i])) & 0xffffffff
	end
	b = (v0 << 32) | v1
	return b
end

local function encrypt(key, plain)
	-- encrypt a text 
	-- key is a 16-byte string
	-- plain is the text to encrypt
	
end --encrypt

local function decrypt(key, plain)

end

------------------------------------------------------------------------
return { -- xtea module
	encrypt = encrypt, 
	decrypt = decrypt, 
	--
	key_size = 16,	-- 128 bits
	block_size = 8,	-- 64 bits
	--
	keysetup = keysetup,
	encryptblock = encryptblock,
	encryptu64 = encryptu64,
	decryptblock = decryptblock,
	decryptu64 = decryptu64,
	
}
	