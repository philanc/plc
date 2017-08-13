-- Copyright (c) 2015  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------
-- sha3 tests

local sha3 = require "plc.sha3"
local bin = require "plc.bin"  -- for hex conversion

local insert, concat = table.insert, table.concat

local function test_sha3()
	-- checked with sha3 512 and 256 on
	-- https://emn178.github.io/online-tools/sha3_512.html
	-- and with Python's hashlib.sha3, thanks to Michael Rosenberg
	-- (https://github.com/doomrobo)
	assert(sha3.hash512("") == bin.hextos[[
		a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6
		15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26 ]])
	assert(sha3.hash512("abc") == bin.hextos[[
		b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e
		10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0 ]])
	assert(sha3.hash512(('1'):rep(128)) == bin.hextos[[
		1e996f94a2c54cacd0fb3a778a3605e34c928bb9f51ffed970f05919dabf2fa3
		fe12d5eafcb8457169846c67b5e30ede9b22c4c59ace3c11663965e4dba28294 ]])
	assert(sha3.hash256("") == bin.hextos[[
		a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a ]])
	assert(sha3.hash256("abc") == bin.hextos[[
		3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532 ]])
	assert(sha3.hash256(('1'):rep(128)) == bin.hextos[[
		fdfe32511b76f38a71a7ac95a4c98add2b41debab35e1b7dda8bb3b14c280533 ]])

	-- check padding (all input sizes modulo 8)
	local st = {
		"", "a", "ab", "abc", "abcd", "abcde", "abcdef", "abcdefg",
		"abcdefgh", "abcdefghi", "abcdefghij"
	}
	local ht = {}  -- hex digest values
	for _, s in ipairs(st) do insert(ht, sha3.hash256(s)) end
	for _, s in ipairs(st) do insert(ht, sha3.hash512(s)) end
	-- results
	local res = concat(ht)

	local expected = bin.hextos[[
a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b
5c828b33397f4762922e39a60c35699d2550466a52dd15ed44da37eb0bdc61e6
3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
6f6f129471590d2c91804c812b5750cd44cbdfb7238541c451e1ea2bc0193177
d716ec61e18904a8f58679b71cb065d4d5db72e0e0c3f155a4feff7add0e58eb
59890c1d183aa279505750422e6384ccb1499c793872d6f31bb3bcaa4bc9f5a5
7d55114476dfc6a2fbeaa10e221a8d0f32fc8f2efb69a6e878f4633366917a62
3e2020725a38a48eb3bbf75767f03a22c6b3f41f459c831309b06433ec649779
f74eb337992307c22bc59eb43e59583a683f3b93077e7f2472508e8c464d2657
d97f84d48722153838d4ede4f8ac5f9dea8abce77cd7367b2eb0dc500a36fbb4

a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26
697f2d856172cb8309d6b8b97dac4de344b549d4dee61edfb4962d8698b7fa803f4f93ff24393586e28b5b957ac3d1d369420ce53332712f997bd336d09ab02a
01c87b5e8f094d8725ed47be35430de40f6ab6bd7c6641a4ecf0d046c55cb468453796bb61724306a5fb3d90fbe3726a970e5630ae6a9cf9f30d2aa062a0175e
b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0
6eb7b86765bf96a8467b72401231539cbb830f6c64120954c4567272f613f1364d6a80084234fa3400d306b9f5e10c341bbdc5894d9b484a8c7deea9cbe4e265
1d7c3aa6ee17da5f4aeb78be968aa38476dbee54842e1ae2856f4c9a5cd04d45dc75c2902182b07c130ed582d476995b502b8777ccf69f60574471600386639b
01309a45c57cd7faef9ee6bb95fed29e5e2e0312af12a95fffeee340e5e5948b4652d26ae4b75976a53cc1612141af6e24df36517a61f46a1a05f59cf667046a
9c93345c31ecffe20a95eca8db169f1b3ee312dd75fb3494cc1dc2f9a2b6092b6cbebf1299ec6d5ba46b08f728f3075109582bc71b97b4deac5122433732234c
c9f25eee75ab4cf9a8cfd44f4992b282079b64d94647edbd88e818e44f701edeb450818f7272cba7a20205b3671ce1991ce9a6d2df8dbad6e0bb3e50493d7fa7
4dbdf4a9fc84c246217a68d5a8f3d2a761766cf78752057d60b730a4a8226ef99bbf580c85468f5e93d8fb7873bbdb0de44314e3adf4b94a4fc37c64ca949c6e
b3e0886fff5ca1df436bf4f6efc124219f908c0abec14036e392a3204f4208b396da0da40e3273f596d4d3db1be4627a16f34230af12ccea92d5d107471551d7
]]

	assert(res == expected)
end

test_sha3()

print("test_sha3: ok")
