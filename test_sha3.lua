-- Copyright (c) 2015  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------
-- sha3 tests

local sha3 = require 'sha3'
local bin = require 'bin'  -- for hex conversion

local function test_sha3()
	-- checked with sha3 512 and 256 on http://sha3calculator.appspot.com/
	assert(bin.stohex(sha3.hash512("")) ==
		"0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304"
	..	"c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e"
	)
	assert(bin.stohex(sha3.hash512("abc")) ==
		"18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5"
	..	"d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96"
	)
	assert(bin.stohex(sha3.hash512(('1'):rep(128))) ==
		"07017910503d61f504f2b93b27a32b8fd7739eb46e83f0dec35c7e17fd639c57"
	..	"e068c654e6a3dab704971a45f58f00368169e4bbbc5b46e1d7c44b567d080b0c"
	)
	assert(bin.stohex(sha3.hash256("")) ==
		"c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
	)
	assert(bin.stohex(sha3.hash256("abc")) ==
		"4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
	)
	assert(bin.stohex(sha3.hash256(('1'):rep(128))) ==
		"573de8614681d466b4a357313565584e4240c32c3d1589f6a64536cce291d654"
	)
end

test_sha3()

print("test_sha3: ok")
