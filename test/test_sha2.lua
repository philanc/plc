-- Copyright (c) 2015  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------
-- sha2 tests

local sha2 = require "plc.sha2"
local bin = require "plc.bin"  -- for hex conversion


local function test_sha2()
	-- checked with sha2 on https://quickhash.com/
	assert(bin.stohex(sha2.hash256("")) ==
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	)
	assert(bin.stohex(sha2.hash256("abc")) ==
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	)
	assert(bin.stohex(sha2.hash256(('1'):rep(128))) ==
		"4ff5ac52aa16dbe3db447ea12d090c5bb6f1325aaaca5ee059b248a89f673972"
	)

	-- tests waiting for hash512 implementation
--~ 	assert(bin.stohex(sha2.hash512("")) ==
--~ 		"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
--~ 	..	"47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
--~ 	)
--~ 	assert(bin.stohex(sha2.hash512("abc")) ==
--~ 		"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
--~ 	..	"2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
--~ 	)
--~ 	assert(bin.stohex(sha2.hash512(('1'):rep(128))) ==
--~ 		"610e0f364ac647d7a78be9e1e4b1f423132a5cb2fa94b0d8baa8d21d42639a77"
--~ 	..	"da897f3d8b3aec464b44d170eb9cf8020b6e4a377672bce649746be941a1d47d"
--~ 	)

end


test_sha2()

print("test_sha2: ok")
