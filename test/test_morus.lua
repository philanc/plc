-- Copyright (c) 2018  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------

--[[

=== test_morus  (morus 1280, with 128 and 256-bit keys)

test vectors from the Morus C reference implementation
http://www3.ntu.edu.sg/home/wuhj/research/caesar/caesar.html


]]

local bin = require "plc.bin"
local stx, xts = bin.stohex, bin.hextos

local mo = require "plc.morus"
local k, iv, m, c, e, m2, err, tag, ad

local function test()
	-- 16-byte key -- 1280_128 -----------------------------------------
	k = xts'00000000000000000000000000000000'
	iv = xts'00000000000000000000000000000000'
	m = ""; ad = ""
	e = mo.aead_encrypt(k, iv, m, ad)
	assert(#e == #ad + #m + 16)
	assert(e == xts"5bd2cba68ea7e72f6b3d0c155f39f962")
	m2, err = mo.aead_decrypt(k, iv, e, #ad)
	assert(m2 == m)
	--
	m = "\x01"; ad = ""
	e = mo.aead_encrypt(k, iv, m, ad)
	assert(e == xts"ba ec1942a315a84695432a1255e6197878")
	m2, err = mo.aead_decrypt(k, iv, e, #ad)
	assert(m2 == m)
	--
	m = ""; ad = "\x01"
	e = mo.aead_encrypt(k, iv, m, ad)
--~ 	print(stx(e))
	assert(e == xts"01 590caa148b848d7614315685377a0d42") --ad,tag
	m2, err = mo.aead_decrypt(k, iv, e, #ad)
	assert(m2 == m)
	--
	k = xts'01000000000000000000000000000000'
	m = "\x00"; ad = "\x00"
	e = mo.aead_encrypt(k, iv, m, ad)
	assert(#e == #ad + #m + 16)
	assert(e == xts"00 cf f9f0a331e3de3293b9dd2e65ba820009")--ad,c,tag
	m2, err = mo.aead_decrypt(k, iv, e, #ad)
	assert(m2 == m)
	--
	k =  xts'00000000000000000000000000000000'
	iv = xts'01000000000000000000000000000000'
	m = "\x00"; ad = "\x00"
	e = mo.aead_encrypt(k, iv, m, ad)
	assert(#e == #ad + #m + 16)
	assert(e == xts"00 09 c957f9ca617876b5205155cd936eb9bb")--ad,c,tag
	m2, err = mo.aead_decrypt(k, iv, e, #ad)
	assert(m2 == m)
	--
	k =  xts'000102030405060708090a0b0c0d0e0f'
	iv = xts'000306090c0f1215181b1e2124272a2d'
	m = xts'01010101010101010101010101010101'
	ad = xts'01010101010101010101010101010101'
	e = mo.aead_encrypt(k, iv, m, ad)
--~ 	print(stx(e))
	assert(#e == #ad + #m + 16)
	assert(e == xts[[
		01010101010101010101010101010101
		b64ee39fc045475e97b41bd08277b4cb
		e989740eb075f75bd57a43a250f53765
		]])--ad,c,tag
	m2, err = mo.aead_decrypt(k, iv, e, #ad)
	assert(m2 == m)
	--
	k =  xts'000102030405060708090a0b0c0d0e0f'
	iv = xts'000306090c0f1215181b1e2124272a2d'
	m = xts[[
	00070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9
	e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9
	c0c7ced5dce3eaf1f8 ]]
	ad = xts[[
	00050a0f14191e23282d32373c41464b50555a5f64696e73787d82878c91969b
	a0a5aaafb4b9be ]]
	e = mo.aead_encrypt(k, iv, m, ad)
--~ 	print(stx(e))
	assert(#e == #ad + #m + 16)
	assert(e == ad .. xts[[
	0861b4924850e8a945e60ec08a1b04f3c77dd2b05ccb05c05c567be8cdfd4582
	28a390c4117b66d71fade7f89902e4d500389a275cb0ce5685f3a21beb6d6519
	f465b96f1eaf9eeea2   5e43f30fa0adb318083a795fc23df52c ]])
	m2, err = mo.aead_decrypt(k, iv, e, #ad)
	assert(m2 == m)
	--
	-- 32-byte key -- 1280_256 -----------------------------------------
	--
	k = xts'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
	iv = xts'000306090c0f1215181b1e2124272a2d'
	m = xts[[ 01010101010101010101010101010101  ]]
	ad = xts[[ 01010101010101010101010101010101 ]]
	e = mo.aead_encrypt(k, iv, m, ad)
	assert(#e == #ad + #m + 16)
	assert(e == ad .. xts[[ 
	aecb6f5991a11746831740e4d45b6c26  c3107488470f05e6828472ac0264045d ]])
	m2, err = mo.aead_decrypt(k, iv, e, #ad)
	assert(m2 == m)
	--
	k = xts'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
	iv = xts'000306090c0f1215181b1e2124272a2d'
	m = xts[[
	00070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9
	e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9
	c0c7ced5dce3eaf1f8  ]]
	ad = xts[[
	00050a0f14191e23282d32373c41464b50555a5f64696e73787d82878c91969b
	a0a5aaafb4b9be ]]
	e = mo.aead_encrypt(k, iv, m, ad)
	assert(#e == #ad + #m + 16)
	assert(e == ad .. xts[[ 
	3e440c73993c55074d4749d6cd8ceddebb95ea8d2387062237349123c75959bf
	a3ff44b18395a0bfc834d5f2de24845bffdba576afab00e798ad5a1666892883
	73f84ead85eb77aa2d      f3166bbf6f94a1932b4b2471e8437206	]])
	m2, err = mo.aead_decrypt(k, iv, e, #ad)
	assert(m2 == m)
	--
end

test()

print("test_morus: ok")
