-- Copyright (c) 2018  Phil Leblanc  -- see LICENSE file
------------------------------------------------------------------------

-- test chacha20.lua


local chacha20 = require "plc.chacha20"

local bin = require "plc.bin"
local stx, xts = bin.stohex, bin.hextos

local function px(s, msg) 
	print("--", msg or "")
	print(stx(s, 16, " ")) 
end

------------------------------------------------------------------------

local function test_chacha20_encrypt()
	-- quick test with RFC 7539 test vector
	local plain =
		"Ladies and Gentlemen of the class of '99: If I could "
	..	"offer you only one tip for the future, sunscreen would be it."
	local key =
		"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
	..	"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
	local nonce = "\x00\x00\x00\x00\x00\x00\x00\x4a\x00\x00\x00\x00"
	assert(#key == chacha20.key_size)
	assert(#nonce == chacha20.nonce_size)
	local counter = 1
	local expected =
	   "\x6e\x2e\x35\x9a\x25\x68\xf9\x80\x41\xba\x07\x28\xdd\x0d\x69\x81"
	.. "\xe9\x7e\x7a\xec\x1d\x43\x60\xc2\x0a\x27\xaf\xcc\xfd\x9f\xae\x0b"
	.. "\xf9\x1b\x65\xc5\x52\x47\x33\xab\x8f\x59\x3d\xab\xcd\x62\xb3\x57"
	.. "\x16\x39\xd6\x24\xe6\x51\x52\xab\x8f\x53\x0c\x35\x9f\x08\x61\xd8"
	.. "\x07\xca\x0d\xbf\x50\x0d\x6a\x61\x56\xa3\x8e\x08\x8a\x22\xb6\x5e"
	.. "\x52\xbc\x51\x4d\x16\xcc\xf8\x06\x81\x8c\xe9\x1a\xb7\x79\x37\x36"
	.. "\x5a\xf9\x0b\xbf\x74\xa3\x5b\xe6\xb4\x0b\x8e\xed\xf2\x78\x5e\x42"
	.. "\x87\x4d"
	local et = chacha20.encrypt(key, counter, nonce, plain)
	assert(et == expected)
	assert(plain == chacha20.encrypt(key, counter, nonce, et))
	--
	-- test some input lengths
	for i = 1, 66 do
		plain = ('p'):rep(i)
		et = chacha20.encrypt(key, counter, nonce, plain)
		local dt = chacha20.decrypt(key, counter, nonce, et)
		assert((#et == #plain) and (dt == plain))
	end
	--
end

local function test_hchacha20()
	-- test vectors from libsodium-1.0.16, xchacha20.c
	local k, n, sk, e
	k = xts[[ 
	24f11cce8a1b3d61e441561a696c1c1b7e173d084fd4812425435a8896a013dc ]]
	n = xts[[ d9660c5900ae19ddad28d6e06e45fe5e ]]
	assert( chacha20.hchacha20(k, n) == xts[[
	5966b3eec3bff1189f831f06afe4d4e3be97fa9235ec8c20d08acfbbb4e851e3 ]] )
	--
	k = xts[[ 
	c49758f00003714c38f1d4972bde57ee8271f543b91e07ebce56b554eb7fa6a7 ]]
	n = xts[[ 31f0204e10cf4f2035f9e62bb5ba7303 ]]
	assert( chacha20.hchacha20(k, n) == xts[[
	0dd8cc400f702d2c06ed920be52048a287076b86480ae273c6d568a2e9e7518c ]] )
	--
end

local function test_xchacha20_encrypt()
	-- test from libsodium-1.0.16
	-- test/aead_xchacha20poly1305.c and aead_xchacha20poly1305.exp
	local k, ctr, n, m, c, e, m2
	k = xts[[ 
	808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f ]]
	ctr = 1
	n = xts[[ 07000000404142434445464748494a4b0000000000000000 ]]
	m = "Ladies and Gentlemen of the class of '99: If I could offer you "
	.. "only one tip for the future, sunscreen would be it."
	e = xts[[
	45 3c 06 93 a7 40 7f 04 ff 4c 56 ae db 17 a3 c0
	a1 af ff 01 17 49 30 fc 22 28 7c 33 db cf 0a c8
	b8 9a d9 29 53 0a 1b b3 ab 5e 69 f2 4c 7f 60 70
	c8 f8 40 c9 ab b4 f6 9f bf c8 a7 ff 51 26 fa ee
	bb b5 58 05 ee 9c 1c f2 ce 5a 57 26 32 87 ae c5
	78 0f 04 ec 32 4c 35 14 12 2c fc 32 31 fc 1a 8b
	71 8a 62 86 37 30 a2 70 2b b7 63 66 11 6b ed 09
	e0 fd 
	]]
	c = chacha20.xchacha20_encrypt(k, ctr, n, m)
 	--px(c)
	assert(c == e)
	m2 = chacha20.xchacha20_decrypt(k, ctr, n, c)
	assert(m2 == m)
	--
	-- test vectors from 
	-- https://github.com/golang/crypto/blob/master/chacha20poly1305/
	--   chacha20poly1305_vectors_test.go
	k = xts[[ 
	194b1190fa31d483c222ec475d2d6117710dd1ac19a6f1a1e8e894885b7fa631 ]]
	ctr = 1
	n = xts[[ 6b07ea26bb1f2d92e04207b447f2fd1dd2086b442a7b6852 ]]
	m = xts[[
	f7e11b4d372ed7cb0c0e157f2f9488d8efea0f9bbe089a345f51bdc77e30d139
	2813c5d22ca7e2c7dfc2e2d0da67efb2a559058d4de7a11bd2a2915e ]]
	e = xts[[
	25ae14585790d71d39a6e88632228a70b1f6a041839dc89a74701c06bfa7c4de
	3288b7772cb2919818d95777ab58fe5480d6e49958f5d2481431014a
	]]
	c = chacha20.xchacha20_encrypt(k, ctr, n, m)
 	--px(c)
	assert(c == e)
	--
	k = xts[[ 
	a60e09cd0bea16f26e54b62b2908687aa89722c298e69a3a22cf6cf1c46b7f8a ]]
	ctr = 1
	n = xts[[ 92da9d67854c53597fc099b68d955be32df2f0d9efe93614 ]]
	m = xts[[
	d266927ca40b2261d5a4722f3b4da0dd5bec74e103fab431702309fd0d0f1a25
	9c767b956aa7348ca923d64c04f0a2e898b0670988b15e ]]
	e = xts[[
	9dd6d05832f6b4d7f555a5a83930d6aed5423461d85f363efb6c474b6c4c826
	1b680dea393e24c2a3c8d1cc9db6df517423085833aa21f ]]
	c = chacha20.xchacha20_encrypt(k, ctr, n, m)
 	--px(c)
	assert(c == e)
	--
end


test_chacha20_encrypt()
test_hchacha20()
test_xchacha20_encrypt()

print("test_chacha20: ok")
