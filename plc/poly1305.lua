-- Copyright (c) 2015  Phil Leblanc  -- see LICENSE file
------------------------------------------------------------
--[[

Poly1305 message authentication (MAC) created by Dan Bernstein

Originally used with AES, then with Salsa20 in the NaCl library.
Used with Chacha20 in recent TLS and SSH [1]

[1] https://en.wikipedia.org/wiki/Poly1305

Specified in RFC 7539 [2] jointly with chacha20 stream encryption and
with an AEAD construction (authenticated encryption with additional
data).

[2] http://www.rfc-editor.org/rfc/rfc7539.txt

This file contains only the poly1305 functions:

	auth(m, k) -> mac
		-- compute the mac for a message m and a key k
		-- this is tha main API of the module

	the following functions should be used only if the MAC must be
	computed over several message parts.

	init(k) -> state
		-- initialize the poly1305 state with a key
	update(state, m) -> state
		-- update the state with a fragment of a message
	finish(state) -> mac
		-- finalize the computation and return the MAC

	Note: several update() can be called between init() and finish().
	For every invocation but the last, the fragment of message m
	passed to update() must have a length multiple of 16 bytes:
		st = init(k)
		update(st, m1) -- here,  #m1 % 16 == 0
		update(st, m2) -- here,  #m2 % 16 == 0
		update(st, m3) -- here,  #m3 can be arbitrary
		mac = finish(st)

	The simple API auth(m, k) is implemented as
		st = init(k)
		update(st, m)  -- #m can be arbitrary
		mac = finish(st)

Credits:
  This poly1305 Lua implementation is based on the cool
  poly1305-donna C 32-bit implementation (just try to figure
  out the h * r mod (2^130-5) computation!) by Andrew Moon,
  https://github.com/floodyberry/poly1305-donna

See also:
  - many chacha20 links at
    http://ianix.com/pub/chacha-deployment.html

]]

-----------------------------------------------------------
-- poly1305

local sunp = string.unpack

local function poly_init(k)
	-- k: 32-byte key as a string
	-- initialize internal state
	local st = {
		r = {
			(sunp('<I4', k,  1)     ) & 0x3ffffff,  --r0
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
	-- return mac 16-byte string
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
-- return poly1305 module

return {
	init = poly_init,
	update = poly_update,
	finish = poly_finish,
	auth = poly_auth,
	verify = poly_verify,
	}
