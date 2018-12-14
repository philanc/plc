-- Copyright (c) 2018  Phil Leblanc  -- see LICENSE file
------------------------------------------------------------
--[[

Chacha20 stream encryption

Pure Lua implementation of the chacha20 algorithm

This implements the IETF variant of  chacha20 encryption
as defined in RFC 7539  (12-byte nonce) and the xchacha20
variant (same encryption algorithm, but with a 24-byte nonce)

For the combined authenticated encryption with associated
data (AEAD) based on chacha20 encryption and poly1305
authentication, see the aead_chacha20.lua file


See also:
- many chacha20 links at
  http://ianix.com/pub/chacha-deployment.html

]]

local app, concat = table.insert, table.concat

------------------------------------------------------------

-- chacha quarter round (rotl inlined)
local function qround(st,x,y,z,w)
	-- st is a chacha state: an array of 16 u32 words
	-- x,y,z,w are indices in st
	local a, b, c, d = st[x], st[y], st[z], st[w]
	local t
	a = (a + b) & 0xffffffff
	--d = rotl32(d ~ a, 16)
	t = d ~ a ; d = ((t << 16) | (t >> (16))) & 0xffffffff
	c = (c + d) & 0xffffffff
	--b = rotl32(b ~ c, 12)
	t = b ~ c ; b = ((t << 12) | (t >> (20))) & 0xffffffff
	a = (a + b) & 0xffffffff
	--d = rotl32(d ~ a, 8)
	t = d ~ a ; d = ((t << 8) | (t >> (24))) & 0xffffffff
	c = (c + d) & 0xffffffff
	--b = rotl32(b ~ c, 7)
	t = b ~ c ; b = ((t << 7) | (t >> (25))) & 0xffffffff
	st[x], st[y], st[z], st[w] = a, b, c, d
	return st
end

-- chacha20 state and working state are allocated once and reused
-- by each invocation of chacha20_block()
local chacha20_state = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
local chacha20_working_state = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}

local chacha20_block = function(key, counter, nonce)
	-- key: u32[8]
	-- counter: u32
	-- nonce: u32[3]
	local st = chacha20_state 		-- state
	local wst = chacha20_working_state 	-- working state
	-- initialize state
	st[1], st[2], st[3], st[4] =
		0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
	for i = 1, 8 do st[i+4] = key[i] end
	st[13] = counter
	for i = 1, 3 do st[i+13] = nonce[i] end
	-- copy state to working_state
	for i = 1, 16 do wst[i] = st[i] end
	-- run 20 rounds, ie. 10 iterations of 8 quarter rounds
	for _ = 1, 10 do           --RFC reference:
		qround(wst, 1,5,9,13)  --1.  QUARTERROUND ( 0, 4, 8,12)
		qround(wst, 2,6,10,14) --2.  QUARTERROUND ( 1, 5, 9,13)
		qround(wst, 3,7,11,15) --3.  QUARTERROUND ( 2, 6,10,14)
		qround(wst, 4,8,12,16) --4.  QUARTERROUND ( 3, 7,11,15)
		qround(wst, 1,6,11,16) --5.  QUARTERROUND ( 0, 5,10,15)
		qround(wst, 2,7,12,13) --6.  QUARTERROUND ( 1, 6,11,12)
		qround(wst, 3,8,9,14)  --7.  QUARTERROUND ( 2, 7, 8,13)
		qround(wst, 4,5,10,15) --8.  QUARTERROUND ( 3, 4, 9,14)
	end
	-- add working_state to state
	for i = 1, 16 do st[i] = (st[i] + wst[i]) & 0xffffffff end
	-- return st, an array of 16 u32 words used as a keystream
	return st
end --chacha20_block()

-- pat16: used to unpack a 64-byte string as 16 uint32
local pat16 = "<I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4"

local function chacha20_encrypt_block(key, counter, nonce, pt, ptidx)
	-- encrypt a 64-byte block of plain text.
	-- key: 32 bytes as an array of 8 uint32
	-- counter: an uint32 (must be incremented for each block)
	-- nonce: 12 bytes as an array of 3 uint32
	-- pt: plain text string,
	-- ptidx: index of beginning of block in plain text (origin=1)
	-- if less than 64 bytes are left at position ptidx, it is padded
	--    with null bytes before encryption and result is stripped
	--    accordingly.
	-- return encrypted block as a string  (length <= 16)
	local rbn = #pt - ptidx + 1 -- number of remaining bytes in pt
	if rbn < 64 then
		local tmp = string.sub(pt, ptidx)
		pt = tmp .. string.rep('\0', 64 - rbn) --pad last block
		ptidx = 1
	end
	assert(#pt >= 64)
	local ba = table.pack(string.unpack(pat16, pt, ptidx))
	local keystream = chacha20_block(key, counter, nonce)
	for i = 1, 16 do
		ba[i] = ba[i] ~ keystream[i]
	end
	local es = string.pack(pat16, table.unpack(ba))
	if rbn < 64 then
		es = string.sub(es, 1, rbn)
	end
	return es
end --chacha20_encrypt_block

local chacha20_encrypt = function(key, counter, nonce, pt)
	-- encrypt plain text 'pt', return encrypted text
	-- key: 32 bytes as a string
	-- counter: an uint32 (must be incremented for each block)
	-- nonce: 8 bytes as a string
	-- pt: plain text string,

	-- ensure counter can fit an uint32 --although it's unlikely
	-- that we hit this wall with pure Lua encryption :-)
	assert((counter + #pt // 64 + 1) < 0xffffffff,
		"block counter must fit an uint32")
	assert(#key == 32, "#key must be 32")
	assert(#nonce == 12, "#nonce must be 12")
	local keya = table.pack(string.unpack("<I4I4I4I4I4I4I4I4", key))
	local noncea = table.pack(string.unpack("<I4I4I4", nonce))
	local t = {} -- used to collect all encrypted blocks
	local ptidx = 1
	while ptidx <= #pt do
		app(t, chacha20_encrypt_block(keya, counter, noncea, pt, ptidx))
		ptidx = ptidx + 64
		counter = counter + 1
	end
	local et = concat(t)
	return et
end --chacha20_encrypt()

local function hchacha20(key, nonce16)
	-- key: string(32)
	-- nonce16: string(16)
	local keya = table.pack(string.unpack("<I4I4I4I4I4I4I4I4", key))
	local noncea = table.pack(string.unpack("<I4I4I4I4", nonce16))
	local st = {}  -- chacha working state
	-- initialize state
	st[1], st[2], st[3], st[4] =
		0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
	for i = 1, 8 do st[i+4] = keya[i] end
	for i = 1, 4 do st[i+12] = noncea[i] end
	-- run 20 rounds, ie. 10 iterations of 8 quarter rounds
	for _ = 1, 10 do              --RFC reference:
		qround(st, 1,5,9,13)  --1.  QUARTERROUND ( 0, 4, 8,12)
		qround(st, 2,6,10,14) --2.  QUARTERROUND ( 1, 5, 9,13)
		qround(st, 3,7,11,15) --3.  QUARTERROUND ( 2, 6,10,14)
		qround(st, 4,8,12,16) --4.  QUARTERROUND ( 3, 7,11,15)
		qround(st, 1,6,11,16) --5.  QUARTERROUND ( 0, 5,10,15)
		qround(st, 2,7,12,13) --6.  QUARTERROUND ( 1, 6,11,12)
		qround(st, 3,8,9,14)  --7.  QUARTERROUND ( 2, 7, 8,13)
		qround(st, 4,5,10,15) --8.  QUARTERROUND ( 3, 4, 9,14)
	end	
	local subkey = string.pack("<I4I4I4I4I4I4I4I4", 
		st[1], st[2], st[3], st[4],
		st[13], st[14], st[15], st[16] )
	return subkey
end --hchacha20()

local function xchacha20_encrypt(key, counter, nonce, pt)
	assert(#key == 32, "#key must be 32")
	assert(#nonce == 24, "#nonce must be 24")
	local subkey = hchacha20(key, nonce:sub(1, 16))
	local nonce12 = '\0\0\0\0'..nonce:sub(17)
	return chacha20_encrypt(subkey, counter, nonce12, pt)
end --xchacha20_encrypt()



------------------------------------------------------------
return {
	chacha20_encrypt = chacha20_encrypt,
	chacha20_decrypt = chacha20_encrypt, -- xor encryption is symmetric
	encrypt = chacha20_encrypt, --alias
	decrypt = chacha20_encrypt, --alias
	hchacha20 = hchacha20,
	xchacha20_encrypt = xchacha20_encrypt,
	xchacha20_decrypt = xchacha20_encrypt,
	--
	key_size = 32,
	nonce_size = 12,  -- nonce size for chacha20_encrypt
	xnonce_size = 24, -- nonce size for xchacha20_encrypt
	}

--end of chacha20
