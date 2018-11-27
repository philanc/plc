-- Copyright (c) 2015  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------
-- sha2 tests

local sha2 = require "plc.sha2"
local bin = require "plc.bin"  -- for hex conversion
local stx, xts = bin.stohex, bin.hextos


local function test_sha2()
	-- checked with sha2 on https://quickhash.com/
	assert(sha2.sha256("") == xts[[
		e3b0c44298fc1c149afbf4c8996fb924
		27ae41e4649b934ca495991b7852b855  ]] )

	assert(sha2.sha256("abc") == xts[[
		ba7816bf8f01cfea414140de5dae2223
		b00361a396177a9cb410ff61f20015ad  ]] )
	
	assert(sha2.sha256(('1'):rep(128)) == xts[[
		4ff5ac52aa16dbe3db447ea12d090c5b
		b6f1325aaaca5ee059b248a89f673972  ]] )
	

	-- tests for sha512 

	assert(sha2.sha512("") == xts[[
		cf83e1357eefb8bdf1542850d66d8007
		d620e4050b5715dc83f4a921d36ce9ce
		47d0d13c5d85f2b0ff8318d2877eec2f
		63b931bd47417a81a538327af927da3e  ]] )
	
	assert(sha2.sha512("abc") == xts[[
		ddaf35a193617abacc417349ae204131
		12e6fa4e89a97ea20a9eeee64b55d39a
		2192992a274fc1a836ba3c23a3feebbd
		454d4423643ce80e2a9ac94fa54ca49f  ]] )
	
	assert(sha2.sha512(('1'):rep(128)) == xts[[
		610e0f364ac647d7a78be9e1e4b1f423
		132a5cb2fa94b0d8baa8d21d42639a77
		da897f3d8b3aec464b44d170eb9cf802
		0b6e4a377672bce649746be941a1d47d  ]] )
	
--[[ more from FIPS 180-4 (added to test padding)
     https://csrc.nist.gov/CSRC/media/Projects/ \
     Cryptographic-Algorithm-Validation-Program/documents/  \
     shs/shabytetestvectors.zip  ]]
	-- 63 bytes
	assert(sha2.sha512(xts[[
	ebb3e2ad7803508ba46e81e220b1cff33ea8381504110e9f8092ef085afef84d
	b0d436931d085d0e1b06bd218cf571c79338da31a83b4cb1ec6c06d6b98768
	]]) == xts[[
	f33428d8fc67aa2cc1adcb2822f37f29cbd72abff68190483e415824f0bcecd4
	47cb4f05a9c47031b9c50e0411c552f31cd04c30cea2bc64bcf825a5f8a66028
	]] )
	-- 64 bytes
	assert(sha2.sha512(xts[[
	c1ca70ae1279ba0b918157558b4920d6b7fba8a06be515170f202fafd36fb7f7
	9d69fad745dba6150568db1e2b728504113eeac34f527fc82f2200b462ecbf5d
	]]) == xts[[
	046e46623912b3932b8d662ab42583423843206301b58bf20ab6d76fd47f1cbb
	cf421df536ecd7e56db5354e7e0f98822d2129c197f6f0f222b8ec5231f3967d
	]] )
	-- 65 bytes
	assert(sha2.sha512(xts[[
	d3ddddf805b1678a02e39200f6440047acbb062e4a2f046a3ca7f1dd6eb03a18
	be00cd1eb158706a64af5834c68cf7f105b415194605222c99a2cbf72c50cb14
	bf  ]]) == xts[[
	bae7c5d590bf25a493d8f48b8b4638ccb10541c67996e47287b984322009d27d
	1348f3ef2999f5ee0d38e112cd5a807a57830cdc318a1181e6c4653cdb8cf122
	]] )
	-- 127 bytes
	assert(sha2.sha512(xts[[
	c13e6ca3abb893aa5f82c4a8ef754460628af6b75af02168f45b72f8f09e45ed
	127c203bc7bb80ff0c7bd96f8cc6d8110868eb2cfc01037d8058992a6cf2effc
	bfe498c842e53a2e68a793867968ba18efc4a78b21cdf6a11e5de821dcabab14
	921ddb33625d48a13baffad6fe8272dbdf4433bd0f7b813c981269c388f001
	]]) == xts[[
	6e56f77f6883d0bd4face8b8d557f144661989f66d51b1fe4b8fc7124d66d9d2
	0218616fea1bcf86c08d63bf8f2f21845a3e519083b937e70aa7c358310b5a7c
	]] )
		
	
----------------------------------------------------------------	
end


test_sha2()

print("test_sha2: ok")
