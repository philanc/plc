--[[
Chacha20 + Poly1305

Pure Lua  implementation
- chacha20 encryption
- poly1305 mac
- authenticated encryption with associated data (AEAD)

Reference:  RFC 7539

Credits:
Poly1305 is based on the cool poly1305-donna C 32-bit implementation 
(just try to figure out the h * r mod (2^130-5) computation!)
by Andrew Moon, https://github.com/floodyberry/poly1305-donna

See also:
- many chacha20 links at
  http://ianix.com/pub/chacha-deployment.html

]]

local spack, sunpack = string.pack, string.unpack

local function stou32a(s)
	-- string -> u32 array
	local a = {}
	local j = 1
	local lbbn = #s % 4
	for i = 1, (#s//4) do
		a[i], j = sunpack('<I4', s, j)
	end
	-- process last bytes if any
	if lbbn > 0 then
		local es = string.sub(s, j)
		for i = lbbn, 4 do es = es .. '\0' end
		a[#a+1] = sunpack('<I4', es)
	end
	return a, lbbn
end

local function u32atos(ua, lbbn)
	-- u32 array -> string
	-- ua: array of u32 words
	-- lbbn: number of bytes to keep in last block if non-zero
	--    must be 0 (keep all bytes) or 1, 2 or 3
	lbbn = lbbn or 0
	local t = {}
	for i, u in ipairs(ua) do
		t[i] = spack('<I4', u)
	end
	if lbbn > 0 then
		lbi = #t
		t[lbi] = string.sub(t[lbi], 1, lbbn)
	end
	return table.concat(t)
end

local function rotr32(i, n)
	-- rorate right on 32 bits
	return ((i >> n) | (i << (32 - n))) & 0xffffffff
end

local function rotl32(i, n)
	-- rorate left on 32 bits
	return ((i << n) | (i >> (32 - n))) & 0xffffffff
end

-- chacha quarter round (initial impl. uses rotl function)
local function qround0(st,x,y,z,w)
	local a, b, c, d = st[x], st[y], st[z], st[w]
	a = (a + b) & 0xffffffff
	d = rotl32(d ~ a, 16)
	c = (c + d) & 0xffffffff
	b = rotl32(b ~ c, 12)
	a = (a + b) & 0xffffffff
	d = rotl32(d ~ a, 8)
	c = (c + d) & 0xffffffff
	b = rotl32(b ~ c, 7)
	st[x], st[y], st[z], st[w] = a, b, c, d
	return st
end


-- chacha quarter round (rotl inlined)
local function qround(st,x,y,z,w)
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
local chacha20_state = {} 
local chacha20_working_state = {} 	 

local chacha20_block = function(key, counter, nonce)
	-- key: u32[16]
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
	-- run 20 rounds, ie. 10 iterations
	for i = 1, 10 do
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
	return st
end --chacha20_block()

local chacha20_encrypt_array = function(key, counter, nonce, pta)
	-- pta: plaintext array of u32 words (4-byte blocks)
	--      pta must contain an exact multiple of 16 u32 words, 
	--      ie. 64-byte blocks
	-- eta: encryptedtext array of u32 words 
	--
	local ptaln = #pta
	-- extend pta to ensure length is multiple of 16
	for j = 1, (#pta//16 +1)*16 - #pta do pta[#pta+1] = 0  end
	local eta = {}
	for j = 0, (#pta // 16) - 1 do --for each 64-byte block
		keystream = chacha20_block(key, counter+j, nonce)
		for i = 1, 16 do -- for each u32 word in block
			eta[16*j + i] = pta[16*j + i] ~ keystream[i] 
		end
	end
	-- adjust eta length
	for i = ptaln+1, #eta do eta[i] = nil end
	return eta
end --chacha20_encrypt_array()

local chacha20_encrypt = function(key, counter, nonce, pt)
	-- encrypt plain text 'pt', return encrypted text
	counter = counter & 0xffffffff  -- counter is u32
	assert(#key == 32, "#key must be 32")
	assert(#nonce == 12, "#nonce must be 12")
	local keya = stou32a(key)
	local noncea = stou32a(nonce)
	local pta, lbbn = stou32a(pt)
	local eta = chacha20_encrypt_array(keya, counter, noncea, pta)
	local et = u32atos(eta, lbbn)
	return et
end --chacha20_encrypt()

------------------------------------------------------------
-- poly1305

local sunp = string.unpack

local function poly_init(k)
	-- k: 32-byte key as a string  
	-- initialize internal state
	local st = {
		r = {	(sunp('<I4', k,  1)     ) & 0x3ffffff,  --r0
			(sunp('<I4', k,  4) >> 2) & 0x3ffff03,  --r1
			(sunp('<I4', k,  7) >> 4) & 0x3ffc0ff,  --r2
			(sunp('<I4', k, 10) >> 6) & 0x3f03fff,  --r3
			(sunp('<I4', k, 13) >> 8) & 0x00fffff,  --r4
		},
		h = { 0,0,0,0,0 },
		pad = {	sunp('<I4', k, 17),  -- 's' in rfc
			sunp('<I4', k, 21),
			sunp('<I4', k, 25),
			sunp('<I4', k, 29),
		},
		buffer = "", -- 
		leftover = 0,
		final = false,
	}--st
	return st
end --poly_init()

local function poly_blocks(st, m)
	-- st: internal state
	-- m: message:string
	local bytes = #m
	local midx = 1
	local hibit = st.final and 0 or 0x01000000 -- 1 << 24
	local r0 = st.r[1]
	local r1 = st.r[2]
	local r2 = st.r[3]
	local r3 = st.r[4]
	local r4 = st.r[5]
	local s1 = r1 * 5
	local s2 = r2 * 5
	local s3 = r3 * 5
	local s4 = r4 * 5
	local h0 = st.h[1]
	local h1 = st.h[2]
	local h2 = st.h[3]
	local h3 = st.h[4]
	local h4 = st.h[5]
	local d0, d1, d2, d3, d4, c
	--
	while bytes >= 16 do  -- 16 = poly1305_block_size
		-- h += m[i]  (in rfc:  a += n with 0x01 byte)
		h0 = h0 + ((sunp('<I4', m, midx     )     ) & 0x3ffffff)
		h1 = h1 + ((sunp('<I4', m, midx +  3) >> 2) & 0x3ffffff)
		h2 = h2 + ((sunp('<I4', m, midx +  6) >> 4) & 0x3ffffff)
		h3 = h3 + ((sunp('<I4', m, midx +  9) >> 6) & 0x3ffffff)
		h4 = h4 + ((sunp('<I4', m, midx + 12) >> 8) | hibit)--0x01 byte
		--
		-- h *= r % p (partial)
		d0 = h0*r0 + h1*s4 + h2*s3 + h3*s2 + h4*s1
		d1 = h0*r1 + h1*r0 + h2*s4 + h3*s3 + h4*s2
		d2 = h0*r2 + h1*r1 + h2*r0 + h3*s4 + h4*s3
		d3 = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s4
		d4 = h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0
		--
		              c = (d0>>26) & 0xffffffff ; h0 = d0 & 0x3ffffff
		d1 = d1 + c ; c = (d1>>26) & 0xffffffff ; h1 = d1 & 0x3ffffff
		d2 = d2 + c ; c = (d2>>26) & 0xffffffff ; h2 = d2 & 0x3ffffff
		d3 = d3 + c ; c = (d3>>26) & 0xffffffff ; h3 = d3 & 0x3ffffff
		d4 = d4 + c ; c = (d4>>26) & 0xffffffff ; h4 = d4 & 0x3ffffff
		h0 = h0 + (c*5) ; c = h0>>26 ; h0 = h0 & 0x3ffffff
		h1 = h1 + c
		--
		midx = midx + 16 -- 16 = poly1305_block_size
		bytes = bytes - 16
	end --while
	st.h[1] = h0
	st.h[2] = h1
	st.h[3] = h2
	st.h[4] = h3
	st.h[5] = h4
	st.bytes = bytes -- remaining bytes. must be < 16 here
	st.midx = midx -- index of first remaining bytes
	return st
end --poly_blocks()

local function poly_update(st, m)	
	-- st: internal state
	-- m: message:string
	st.bytes, st.midx = #m, 1
	-- process full blocks if any
	if st.bytes >= 16 then 
		poly_blocks(st, m) 
	end
	--handle remaining bytes
	if st.bytes == 0 then -- no bytes left
		-- nothing to do? no add 0x01? - apparently not.
	else
		local buffer = 	string.sub(m, st.midx) 
			.. '\x01' .. string.rep('\0', 16 - st.bytes -1)
		assert(#buffer == 16)
		st.final = true  -- this is the last block
--~ 		p16(buffer)
		poly_blocks(st, buffer)
	end
	--
	return st
end --poly_update

local function poly_finish(st)
	--
	local c, mask 	--u32
	local f  	--u64
	-- fully carry h
	local h0 = st.h[1]
	local h1 = st.h[2]
	local h2 = st.h[3]
	local h3 = st.h[4]
	local h4 = st.h[5]
	--
		         c = h1 >> 26; h1 = h1 & 0x3ffffff
	h2 = h2 +     c; c = h2 >> 26; h2 = h2 & 0x3ffffff
	h3 = h3 +     c; c = h3 >> 26; h3 = h3 & 0x3ffffff
	h4 = h4 +     c; c = h4 >> 26; h4 = h4 & 0x3ffffff
	h0 = h0 + (c*5); c = h0 >> 26; h0 = h0 & 0x3ffffff
	h1 = h1 + c
	--
	--compute h + -p
	local g0 = (h0 + 5) ; c = g0 >> 26; g0 = g0 & 0x3ffffff
	local g1 = (h1 + c) ; c = g1 >> 26; g1 = g1 & 0x3ffffff
	local g2 = (h2 + c) ; c = g2 >> 26; g2 = g2 & 0x3ffffff
	local g3 = (h3 + c) ; c = g3 >> 26; g3 = g3 & 0x3ffffff
	local g4 = (h4 + c - 0x4000000) &0xffffffff  -- (1 << 26)
	--
	-- select h if h < p, or h + -p if h >= p
	mask = ((g4 >> 31) -1) & 0xffffffff
	--
	g0 = g0 & mask
	g1 = g1 & mask
	g2 = g2 & mask
	g3 = g3 & mask
	g4 = g4 & mask
	--
	mask = (~mask)  & 0xffffffff
	h0 = (h0 & mask) | g0
	h1 = (h1 & mask) | g1
	h2 = (h2 & mask) | g2
	h3 = (h3 & mask) | g3
	h4 = (h4 & mask) | g4
	--
	--h = h % (2^128)
	h0 = ((h0      ) | (h1 << 26)) & 0xffffffff
	h1 = ((h1 >>  6) | (h2 << 20)) & 0xffffffff
	h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff
	h3 = ((h3 >> 18) | (h4 <<  8)) & 0xffffffff
	--
	-- mac = (h + pad) % (2^128)
	f = h0 + st.pad[1]             ; h0 = f & 0xffffffff
	f = h1 + st.pad[2] + (f >> 32) ; h1 = f & 0xffffffff
	f = h2 + st.pad[3] + (f >> 32) ; h2 = f & 0xffffffff
	f = h3 + st.pad[4] + (f >> 32) ; h3 = f & 0xffffffff
	-- 
	local mac = string.pack('<I4I4I4I4', h0, h1, h2, h3)
	-- (should zero out the state?)
	-- 
	return mac
end --poly_finish()

local function poly_auth(m, k)
	-- m: msg string
	-- k: key string (must be 32 bytes)
	assert(#k == 32)
	local st = poly_init(k)
	poly_update(st, m)
	local mac = poly_finish(st)
	return mac
end --poly_auth()

local function poly_verify(m, k, mac)
	local macm = poly_auth(m, k)
	return macm == mac
end --poly_verify()

------------------------------------------------------------
-- poly1305 key generation and AEAD function

local poly_keygen = function(key, nonce)
	local counter = 0
	local keya = stou32a(key)
	local noncea = stou32a(nonce)
	local block = chacha20_block(keya, counter, noncea)
	-- keep only first the 256 bits (8 u32 words)
	for i = 9, 16 do block[i] = nil end
	return u32atos(block)
end

local pad16 = function(s)
	-- return null bytes to add to s so that #s is a multiple of 16 
	return (#s % 16 == 0) and "" or ('\0'):rep(16 - (#s % 16))
end

local app = table.insert

local chacha20_aead_encrypt = function(aad, key, iv, constant, plain)
	-- RFC 7539 sect 2.8.1
	-- (memory inefficient - encr text is copied in mac_data)
	local mt = {} -- mac_data table
	local nonce = constant .. iv
	local otk = poly_keygen(key, nonce)
	local encr = chacha20_encrypt(key, 1, nonce, plain)
	app(mt, aad) 
	app(mt, pad16(aad)) 
	app(mt, encr) 
--~ 	p16('encr', encr)
	app(mt, pad16(encr)) 
	-- aad and encrypted text length must be encoded as 
	-- little endian _u64_ (and not u32) -- see errata at
	-- https://www.rfc-editor.org/errata_search.php?rfc=7539
	app(mt, string.pack('<I8', #aad))
	app(mt, string.pack('<I8', #encr))
	local mac_data = table.concat(mt)
--~ 	p16('mac', mac_data)
	local tag = poly_auth(mac_data, otk)
	return encr, tag
end --chacha20_aead_encrypt()

local function chacha20_aead_decrypt(aad, key, iv, constant, encr, tag)
	-- (memory inefficient - encr text is copied in mac_data)
	-- (structure similar to aead_encrypt => what could be factored?)
	local mt = {} -- mac_data table
	local nonce = constant .. iv
	local otk = poly_keygen(key, nonce)
	local plain = chacha20_encrypt(key, 1, nonce, encr)
	app(mt, aad) 
	app(mt, pad16(aad)) 
	app(mt, encr) 
	app(mt, pad16(encr)) 
	app(mt, string.pack('<I8', #aad))
	app(mt, string.pack('<I8', #encr))
	local mac_data = table.concat(mt)
	local mac = poly_auth(mac_data, otk)
	if mac == tag then 
		local plain = chacha20_encrypt(key, 1, nonce, encr)
		return plain
	else
		return nil, "auth failed"
	end
end --chacha20_aead_decrypt()


------------------------------------------------------------
-- return chacha20poly1305 module

local cha = {
	chacha20_encrypt_array = chacha20_encrypt_array, 
	chacha20_encrypt = chacha20_encrypt, 
	poly_auth = poly_auth,
	poly_verify = poly_verify,
	poly_keygen = poly_keygen,
	chacha20_aead_encrypt = chacha20_aead_encrypt,
	chacha20_aead_decrypt = chacha20_aead_decrypt,
	}

return cha
