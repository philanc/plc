-- Copyright (c) 2015  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------
--[[

ec25519 - curve25519 scalar multiplication

Ported to Lua from the original C tweetnacl implementation,
(public domain, by Dan Bernstein, Tanja Lange et al
see http://tweetnacl.cr.yp.to/ )

To make debug and validation easier, the original code structure
and function names have been conserved as much as possible.



]]

------------------------------------------------------------

-- set25519() not used

local function car25519(o)
	local c
	for i = 1, 16 do
		o[i] = o[i] + 65536 -- 1 << 16
		-- lua ">>" doesn't perform sign extension...
		-- so the following >>16 doesn't work with negative numbers!!
		-- ...took a bit of time to find this one :-)
		-- c = o[i] >> 16
		c = o[i] // 65536
		if i < 16 then
			o[i+1] = o[i+1] + (c - 1)
		else
			o[1] = o[1] + 38 * (c - 1)
		end
		o[i] = o[i] - (c << 16)
	end
end --car25519()

local function sel25519(p, q, b)
	local c = ~(b-1)
	local t
	for i = 1, 16 do
		t = c & (p[i] ~ q[i])
		p[i] = p[i] ~ t
		q[i] = q[i] ~ t
	end
end --sel25519

local function pack25519(o, n)
	-- out o[32], in n[16]
	local m, t = {}, {}
	local b
	for i = 1, 16 do t[i] = n[i] end
	car25519(t)
	car25519(t)
	car25519(t)
	for _ = 1, 2 do
		m[1] = t[1] - 0xffed
		for i = 2, 15 do
			m[i] = t[i] - 0xffff - ((m[i-1] >> 16) & 1)
			m[i-1] = m[i-1] & 0xffff
		end
		m[16] = t[16] - 0x7fff - ((m[15] >> 16) & 1)
		b = (m[16] >> 16) & 1
		m[15] = m[15] & 0xffff
		sel25519(t, m, 1-b)
	end
	for i = 1, 16 do
		o[2*i-1] = t[i] & 0xff
		o[2*i] = t[i] >> 8
	end
end -- pack25519

-- neq25519() not used
-- par25519() not used

local function unpack25519(o, n)
	-- out o[16], in n[32]
	for i = 1, 16 do
		o[i] = n[2*i-1] + (n[2*i] << 8)
	end
	o[16] = o[16] & 0x7fff
end -- unpack25519

local function A(o, a, b) --add
	for i = 1, 16 do o[i] = a[i] + b[i] end
end

local function Z(o, a, b) --sub
	for i = 1, 16 do o[i] = a[i] - b[i] end
end

local function M(o, a, b) --mul  gf, gf -> gf
	local t = {}
	for i = 1, 32 do t[i] = 0  end
	for i = 1, 16 do
		for j = 1, 16 do
			t[i+j-1] = t[i+j-1] + (a[i] * b[j])
		end
	end
	for i = 1, 15 do t[i] = t[i] + 38 * t[i+16] end
	for i = 1, 16 do o[i] = t[i] end
	car25519(o)
	car25519(o)
end

local function S(o, a)  --square
	M(o, a, a)
end

local function inv25519(o, i)
	local c = {}
	for a = 1, 16 do c[a] = i[a] end
	for a = 253, 0, -1 do
		S(c, c)
		if a ~= 2 and a ~= 4 then M(c, c, i) end
	end
	for a = 1, 16 do o[a] = c[a] end
--~ 	pt(o)
end

--pow2523() not used

local t_121665 = {0xDB41,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0}

local function crypto_scalarmult(q, n, p)
	-- out q[], in n[], in p[]
	local z = {}
	local x = {}
	local a = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
	local b = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
	local c = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
	local d = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
	local e = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
	local f = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
	for i = 1, 31 do z[i] = n[i] end
	z[32] = (n[32] & 127) | 64
	z[1] = z[1] & 248
--~ 	pt(z)
	unpack25519(x, p)
--~ 	pt(x)
	for i = 1, 16 do
		b[i] = x[i]
		a[i] = 0
		c[i] = 0
		d[i] = 0
	end
	a[1] = 1
	d[1] = 1
	for i = 254, 0, -1 do
		local r = (z[(i>>3)+1] >> (i & 7)) & 1
		sel25519(a,b,r)
		sel25519(c,d,r)
		A(e,a,c)
		Z(a,a,c)
		A(c,b,d)
		Z(b,b,d)
		S(d,e)
		S(f,a)
		M(a,c,a)
		M(c,b,e)
		A(e,a,c)
		Z(a,a,c)
		S(b,a)
		Z(c,d,f)
		M(a,c,t_121665)
		A(a,a,d)
		M(c,c,a)
		M(a,d,f)
		M(d,b,x)
		S(b,e)
		sel25519(a,b,r)
		sel25519(c,d,r)
	end
	for i = 1, 16 do
		x[i+16] = a[i]
		x[i+32] = c[i]
		x[i+48] = b[i]
		x[i+64] = d[i]
	end
	-- cannot use pointer arithmetics...
	local x16, x32 = {}, {}
	for i = 1, #x do
		if i > 16 then x16[i-16] = x[i] end
		if i > 32 then x32[i-32] = x[i] end
	end
	inv25519(x32,x32)
	M(x16,x16,x32)
	pack25519(q,x16)
	return 0
end -- crypto_scalarmult

local t_9 = { -- u8 * 32
	9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	}

local function crypto_scalarmult_base(q, n)
	-- out q[], in n[]
	return crypto_scalarmult(q, n, t_9)
end

------------------------------------------------------------------------
-- convenience function (using binary strings instead of byte tables)
--
-- curve point and scalars are represented as 32-byte binary strings
-- (encoded as little endian)

local function scalarmult(n, p)
	-- n, a scalar (little endian) as a 32-byte string
	-- p, a curve point as a 32-byte string
	-- return the scalar product np as a 32-byte string
	local qt, nt, pt = {}, {}, {} 
	for i = 1, 32 do 
		nt[i] = string.byte(n, i) 
		pt[i] = string.byte(p, i) 
	end
	crypto_scalarmult(qt, nt, pt)
	local q = string.char(table.unpack(qt))
	return q
end

-- base: the curve point generator = 9

local base = '\9' .. ('\0'):rep(31)

--[[

--- How to use scalarmult to generate curve25519 keypairs

For any scalar s (a 32-byte string), the scalar product 's . base' is a point on the elliptic curve. 'base' is a generator.
	point = scalarmult(s, base)

	If s2 is another scalar, 
	point2 = scalarmult(s2, point) is also a point on the curve.

Secret keys are random scalars (a 32-byte random string).
The associated public keys are the corresponding points on the curve
(also encoded as 32-byte strings):
   public = scalarmult(secret, base)

let 'ask' and 'bsk' be repectively Alice and Bob private keys 
(random 32-byte strings)

Alice public key 'apk' is obtained by:
   apk = scalarmult(ask, base)

Similarly for Bob public key 'bpk':
   bpk = scalarmult(bsk, base)

--- How to perform an ECDH exchange

When Alice wants to send a message to Bob, they must be able to establish
a common session key (for a symmetric encryption algorithm).

   Alice and Bob each have the public key of the other party.
   
   Alice compute a secret s:
   s = scalarmult(ask, bpk)
   
   Bob is able to compute the same secret s as:
   s = scalarmult(bsk, apk)
   
   This is the same secret since apk = ask . base and bpk = bsk . base
   thus:  s = ask . bsk . base = bsk . ask . base since the scalar
   multiplication is commutative

   the secret s is a 32-byte string. It is advised not to use it
   directly as a session key since the bit dstribution in s is not 
   completely uniform. So the secret s should be "washed" with 
   a cryptographic hash function to get a uniformly distributed key.
   
   NaCl use the Salsa20 core encryption function to do that (see
   the hsalsa20() function and the stream_key() function in file
   box.lua
   
   But any other hash function can do. (eg. sha256 or blake2b)

--- scalarmult implementation notes

- scalars are represented as little endian

- the 3 lower bits of the scalar are ignored (the actual scalar 
  is contained in bits 3 to 255)
  so for example, 
   scalarmult(('\0'):rep(32), base)
   == scalarmult('\6' .. ('\0'):rep(31), base)

- the bit 254 of the scalar is always set. so:
   scalarmult(('\0'):rep(32), base)
   == scalarmult(('\0'):rep(31) .. '\x40', base)

- the group order N is (2^252 + 27742317777372353535851937790883648493)
  let N8 the 32-byte string containing 8 * N as a little endian 
  32-byte int. (the hex rep of the 32-byte string is: 
  689faee7d21893c0b2e6bc17f5cef7a600000000000000000000000000000080 )
  then,
     scalarmult(('\0'):rep(32), base) == scalarmult(N8, base)
  
  
  
]]


return {
	crypto_scalarmult = crypto_scalarmult,
	crypto_scalarmult_base = crypto_scalarmult_base,
	--
	-- convenience function and definition
	--
	scalarmult = scalarmult,
	base = base,
	--
}
 -- end of ec25519 module



