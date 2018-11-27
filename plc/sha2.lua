-- Copyright (c) 2018  Phil Leblanc  -- see LICENSE file
------------------------------------------------------------------------

--        SHA2-256 and SHA2-512 -- see RFC 6234


-- sha2-256 initially based on code written by Roberto Ierusalimschy
-- for an early Lua 5.3rc with (un)packint() functions.
-- published by  Roberto on the Lua mailing list
-- http://lua-users.org/lists/lua-l/2014-03/msg00851.html
-- can be distributed under the MIT License terms. see:
-- http://lua-users.org/lists/lua-l/2014-08/msg00628.html
--
-- adapted to 5.3 (string.(un)pack()) --phil, 150827
--
-- optimized for performance, 181008. The core permutation
-- for sha2-256 and sha2-512 is lifted from the very good
-- implementation by Egor Skriptunoff, also MIT-licensed. See
-- https://github.com/Egor-Skriptunoff/pure_lua_SHA2


------------------------------------------------------------
-- local declarations

local string, assert = string, assert
local spack, sunpack = string.pack, string.unpack 

------------------------------------------------------------------------
-- sha256

-- Initialize table of round constants
-- (first 32 bits of the fractional parts of the cube roots of the first
-- 64 primes 2..311)
local k256 = {
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
   0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
   0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
   0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
   0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
   0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
   0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
   0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
   0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

local function pad64(msg, len)
	local extra = 64 - ((len + 1 + 8) % 64)
	len = spack(">I8", len * 8)    -- original len in bits, coded
	msg = msg .. "\128" .. string.rep("\0", extra) .. len
	assert(#msg % 64 == 0)
	return msg
end

local ww256 = {}
	  
local function sha256 (msg)
	msg = pad64(msg, #msg)
	local h1, h2, h3, h4, h5, h6, h7, h8 = 
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	local k = k256
	local w = ww256
	local mlen = #msg
  	-- Process the message in successive 512-bit (64 bytes) chunks:
	for i = 1, mlen, 64 do
		w[1], w[2], w[3], w[4], w[5], w[6], w[7], w[8], 
		w[9], w[10], w[11], w[12], w[13], w[14], w[15], w[16]
		= sunpack(">I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4", msg, i)
		-- mix msg block in state
		for j = 17, 64 do
			local x = w[j - 15]; x = (x << 32) | x
			local y = w[j - 2]; y = (y << 32) | y
			w[j] = (  ((x >> 7) ~ (x >> 18) ~ (x >> 35))
				+ ((y >> 17) ~ (y >> 19) ~ (y >> 42))
				+ w[j - 7] + w[j - 16]  ) & 0xffffffff
		end
		local a, b, c, d, e, f, g, h = h1, h2, h3, h4, h5, h6, h7, h8
		-- main state permutation
		for j = 1, 64 do
			e = (e << 32) | (e & 0xffffffff)
			local t1 = ((e >> 6) ~ (e >> 11) ~ (e >> 25))
				+ (g ~ e & (f ~ g)) + h + k[j] + w[j]
			h = g
			g = f
			f = e
			e = (d + t1) 
			d = c
			c = b
			b = a
			a = (a << 32) | (a & 0xffffffff)
			a = t1 	+ ((a ~ c) & d ~ a & c) 
				+ ((a >> 2) ~ (a >> 13) ~ (a >> 22))
		end
		h1 = h1 + a
		h2 = h2 + b 
		h3 = h3 + c 
		h4 = h4 + d 
		h5 = h5 + e 
		h6 = h6 + f 
		h7 = h7 + g 
		h8 = h8 + h 
	end
	-- clamp hash to 32-bit words
	h1 = h1 & 0xffffffff
	h2 = h2 & 0xffffffff
	h3 = h3 & 0xffffffff
	h4 = h4 & 0xffffffff
	h5 = h5 & 0xffffffff
	h6 = h6 & 0xffffffff
	h7 = h7 & 0xffffffff
	h8 = h8 & 0xffffffff
	-- return hash as a binary string
	return spack(">I4I4I4I4I4I4I4I4", h1, h2, h3, h4, h5, h6, h7, h8)
end --sha256

------------------------------------------------------------------------
-- sha512

local k512 = {
0x428a2f98d728ae22,0x7137449123ef65cd,0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc,
0x3956c25bf348b538,0x59f111f1b605d019,0x923f82a4af194f9b,0xab1c5ed5da6d8118,
0xd807aa98a3030242,0x12835b0145706fbe,0x243185be4ee4b28c,0x550c7dc3d5ffb4e2,
0x72be5d74f27b896f,0x80deb1fe3b1696b1,0x9bdc06a725c71235,0xc19bf174cf692694,
0xe49b69c19ef14ad2,0xefbe4786384f25e3,0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65,
0x2de92c6f592b0275,0x4a7484aa6ea6e483,0x5cb0a9dcbd41fbd4,0x76f988da831153b5,
0x983e5152ee66dfab,0xa831c66d2db43210,0xb00327c898fb213f,0xbf597fc7beef0ee4,
0xc6e00bf33da88fc2,0xd5a79147930aa725,0x06ca6351e003826f,0x142929670a0e6e70,
0x27b70a8546d22ffc,0x2e1b21385c26c926,0x4d2c6dfc5ac42aed,0x53380d139d95b3df,
0x650a73548baf63de,0x766a0abb3c77b2a8,0x81c2c92e47edaee6,0x92722c851482353b,
0xa2bfe8a14cf10364,0xa81a664bbc423001,0xc24b8b70d0f89791,0xc76c51a30654be30,
0xd192e819d6ef5218,0xd69906245565a910,0xf40e35855771202a,0x106aa07032bbd1b8,
0x19a4c116b8d2d0c8,0x1e376c085141ab53,0x2748774cdf8eeb99,0x34b0bcb5e19b48a8,
0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb,0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3,
0x748f82ee5defb2fc,0x78a5636f43172f60,0x84c87814a1f0ab72,0x8cc702081a6439ec,
0x90befffa23631e28,0xa4506cebde82bde9,0xbef9a3f7b2c67915,0xc67178f2e372532b,
0xca273eceea26619c,0xd186b8c721c0c207,0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178,
0x06f067aa72176fba,0x0a637dc5a2c898a6,0x113f9804bef90dae,0x1b710b35131c471b,
0x28db77f523047d84,0x32caab7b40c72493,0x3c9ebe0a15c9bebc,0x431d67c49c100d4c,
0x4cc5d4becb3e42b6,0x597f299cfc657e2a,0x5fcb6fab3ad6faec,0x6c44198c4a475817
}

local function pad128(msg, len)
	local extra = 128 - ((len + 1 + 8) % 128)
	len = spack(">I8", len * 8)    -- original len in bits, coded
	msg = msg .. "\128" .. string.rep("\0", extra) .. len
	assert(#msg % 128 == 0)
	return msg
end

local ww512 = {}
	  
local function sha512 (msg)
	msg = pad128(msg, #msg)
	local h1, h2, h3, h4, h5, h6, h7, h8 = 
		0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
		0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
		0x510e527fade682d1, 0x9b05688c2b3e6c1f,
		0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
	local k = k512
	local w = ww512 -- 80 * i64 state
	local mlen = #msg
  	-- Process the message as 128-byte blocks:
	-- (this is borrowed to Egor Skriptunoff's pure_lua_SHA2
	-- https://github.com/Egor-Skriptunoff/pure_lua_SHA2)
	for i = 1, mlen, 128 do
		w[1], w[2], w[3], w[4], w[5], w[6], w[7], w[8], 
		w[9], w[10], w[11], w[12], w[13], w[14], w[15], w[16]
		= sunpack(">i8i8i8i8i8i8i8i8i8i8i8i8i8i8i8i8", msg, i)
		-- mix msg block in state

		for j = 17, 80 do
			local a = w[j-15]
			local b = w[j-2]
			w[j] = (a >> 1 ~ a >> 7 ~ a >> 8 ~ a << 56 ~ a << 63)
			  + (b >> 6 ~ b >> 19 ~ b >> 61 ~ b << 3 ~ b << 45) 
			  + w[j-7] + w[j-16]
		end
		local a, b, c, d, e, f, g, h = h1, h2, h3, h4, h5, h6, h7, h8
		-- main state permutation
		for j = 1, 80 do
			local z = (e >> 14 ~ e >> 18 ~ e >> 41 ~ e << 23 
				   ~ e << 46 ~ e << 50) 
				+ (g ~ e & (f ~ g)) + h + k[j] + w[j]
			h = g
			g = f
			f = e
			e = z + d
			d = c
			c = b
			b = a
			a = z + ((a ~ c) & d ~ a & c) 
			      + (a >> 28 ~ a >> 34 ~ a >> 39 ~ a << 25 
				~ a << 30 ~ a << 36)
		end
		h1 = h1 + a
		h2 = h2 + b 
		h3 = h3 + c 
		h4 = h4 + d 
		h5 = h5 + e 
		h6 = h6 + f 
		h7 = h7 + g 
		h8 = h8 + h 
	end
	-- return hash as a binary string
	return spack(">i8i8i8i8i8i8i8i8", h1, h2, h3, h4, h5, h6, h7, h8)
end --sha512

------------------------------------------------------------------------

return {
  sha256 = sha256,
  sha512 = sha512,
}

