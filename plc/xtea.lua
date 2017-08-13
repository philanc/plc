-- Copyright (c) 2015  Phil Leblanc  -- see LICENSE file
------------------------------------------------------------------------
--[[ 		** WORK IN PROGRESS  --  CANNOT BE USED AS-IS **

XTEA module

-- main API (stream encryption in CTR mode)
encrypt		- encrypt a string
decrypt		- decrypt a string (an alias for encrypt)

-- core functions (maybe used for other modes or special use cases)
keysetup	- setup an XTEA key (pre-computes constants)
encrypt_u64	- encrypt a 8-byte block (encoded as a uint64)
decrypt_u64	- decrypt a 8-byte block (encoded as a uint64)

------------------------------------------------------------------------

The XTEA block cipher was designed by Roger Needham
and David Wheeler in 1997

see Wikipedia page
https://en.wikipedia.org/wiki/XTEA

This implementation is based on the public domain C code included
on the Wikipedia page (modified to precompute the "sum + key[...]" terms)

]]

------------------------------------------------------------------------
-- debug functions (should be removed)

local bin = require "plc.bin"
local stx = bin.stohex
local xts = bin.hextos
local function px(s) print(stx(s, 16, " ")) end
local function pf(...) print(string.format(...)) end
local function p8(b) print(string.format("%016x", b)) end

------------------------------------------------------------------------
-- local definitions

local spack, sunpack = string.pack, string.unpack
local app, concat = table.insert, table.concat

------------------------------------------------------------------------
-- core XTEA encryption/decryption

local ROUNDS = 32

local function keysetup(key)
	-- key is a 16-byte string (128-bit key)
	-- precompute "sum + key[]"
	-- returns a "state" with both tables (2 * 32 * uint32)
	assert(#key == 16)
	local kt = { 0,0,0,0 }
	kt[1], kt[2], kt[3], kt[4] = sunpack('>I4I4I4I4', key)
	local skt0 = {} -- the "sum + key[sum&3]" table
	local skt1 = {} -- the "sum + key[sum>>11 & 3]" table
	local sum, delta = 0, 0x9E3779B9
	for i = 1, ROUNDS do
		skt0[i] = sum + kt[(sum & 3) + 1]
		sum = (sum + delta) & 0xffffffff
		skt1[i] = sum + kt[((sum>>11) & 3) + 1]
	end
	return { skt0=skt0, skt1=skt1, }
end

local function encrypt_u64(st, bu)
	-- st: state, produced by keysetup
	-- ub: 64-bit block as a uint64 (big endian - unpack with ">I8")
	local skt0, skt1 = st.skt0, st.skt1
	-- xtea works on big endian numbers: v0 is MSB, v1 is LSB
	local v0, v1 = bu >> 32, bu & 0xffffffff
--~ 	p8(v0);p8(v1);p8(b)
	local sum, delta = 0, 0x9E3779B9
	for i = 1, ROUNDS do
		v0 = (v0 + ((((v1<<4) ~ (v1>>5)) + v1) ~ skt0[i])) & 0xffffffff
		v1 = (v1 + ((((v0<<4) ~ (v0>>5)) + v0) ~ skt1[i])) & 0xffffffff
	end
	bu = (v0 << 32) | v1
	return bu
end

local function decrypt_u64(st, bu)
	-- st: state, produced by keysetup
	-- bu: 64-bit encrypted block as a uint64 (big endian)
	-- returns decrypted block as a uint64
	local skt0, skt1 = st.skt0, st.skt1
	local v0, v1 = bu >> 32, bu & 0xffffffff
	local sum, delta = 0, 0x9E3779B9
	for i = ROUNDS, 1, -1 do
		v1 = (v1 - ((((v0<<4) ~ (v0>>5)) + v0) ~ skt1[i])) & 0xffffffff
		v0 = (v0 - ((((v1<<4) ~ (v1>>5)) + v1) ~ skt0[i])) & 0xffffffff
	end
	bu = (v0 << 32) | v1
	return bu
end

-- to encrypt/decrypt an 8-byte string (eg. for ECB mode),
-- use the following:
-- encrypt:  spack(">I8", encrypt_u64(st, sunpack(">I8", b)))
-- decrypt:  spack(">I8", decrypt_u64(st, sunpack(">I8", b)))

-- convenience functions: same core encryption/decryption
-- but the block parameter is a 8-byte string instead of a uint64
-- [hmm, not sure I will keep these two...]

local function encrypt_s8(st, b)
	return spack(">I8", encrypt_u64(st, (sunpack(">I8", b))))
end

local function decrypt_s8(st, b)
	return spack(">I8", decrypt_u64(st, (sunpack(">I8", b))))
end


------------------------------------------------------------------------
-- stream encryption

local function xtea_ctr(key, iv, itxt)
	-- encrypt/decrypt a text (stream en/decryption in CTR mode
	--   (the counter is the index in the input text. It is XORed
	--	  with the IV at each block )
	-- key is a 16-byte string
	-- iv is a 8-byte string
	-- itxt is the text to encrypt/decrypt
	-- returns the encrypted/decrypted text
	--
	assert(#key == 16, "bad key length")
	assert(#iv == 8, "bad IV length")
	-- special case: empty string
	if #itxt == 0 then return "" end
	local ivu = sunpack("<I8", iv) -- IV as a uint64
	local ot = {}  -- a table to collect output
	local rbn = #itxt   -- number of remaining bytes
	local ksu  	-- keystream for one plain block, as a uint64
	local ibu	-- an input block, as a uint64
	local ob	-- an output block as a string
	local st = keysetup(key)
	for i = 1, #itxt, 8 do
		ksu = encrypt_u64(st, ivu ~ i)
		if rbn < 8 then
			local buffer = string.sub(itxt, i) .. string.rep('\0', 8 - rbn)
			ibu = sunpack("<I8", buffer)
			ob = string.sub(spack("<I8", ibu ~ ksu), 1, rbn)
		else
			ibu = sunpack("<I8", itxt, i)
			ob = spack("<I8", ibu ~ ksu)
			rbn = rbn - 8
		end
		app(ot, ob)
	end
	return concat(ot)
end --xtea_ctr


------------------------------------------------------------------------
return { -- xtea module
	--
	-- main API (stream encryption)
	xtea_ctr = xtea_ctr,
	encrypt = xtea_ctr,
	decrypt = xtea_ctr,
	--
	-- cipher parameters
	key_size = 16,	-- 128 bits
	block_size = 8,	-- 64 bits
	--
	-- raw functions for more complex scenarios
	keysetup = keysetup,
	encrypt_u64 = encrypt_u64,
	decrypt_u64 = decrypt_u64,
	encrypt_s8 = encrypt_s8,	-- not sure it will stay...
	decrypt_s8 = decrypt_s8,	-- not sure it will stay...

}
