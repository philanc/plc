-- Copyright (c) 2017 Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------
-- blake2b tests

local blake2b = require "plc.blake2b"

local bin = require "plc.bin"  -- for hex conversion

local hextos = bin.hextos

------------------------------------------------------------------------

local function test_blake2b()
	local a, b
	--
	a = blake2b.hash("")
	b = hextos[[
	786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419
	d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce ]]
	assert(a == b)
	--
	a = blake2b.hash("abc")
	b = hextos[[
	ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1
	7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923 ]]
	assert(a == b)
	--
	a = blake2b.hash("The quick brown fox jumps over the lazy dog")
	b = hextos[[
	a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673
	f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918 ]]
	assert(a == b)
	--
	a = blake2b.hash(('a'):rep(1000))
	b = hextos[[
	d6a69459fe93fc6b9537ed4336e5099e0dcca3e97290a412500ed7a0daffb03d
	80cf3650a20e0591f748e10c3c534945ee83d5f2c9722f1a68d98b8c01af23fd ]]
	assert(a == b)
	--
	-- test multiple updates
	local ctx
	ctx = blake2b.init()
	blake2b.update(ctx, ('a'):rep(500))
	blake2b.update(ctx, ('a'):rep(500))
	a = blake2b.final(ctx)
	assert(a == b)
	--
	ctx = blake2b.init()
	for _ = 1, 100 do blake2b.update(ctx, ('a'):rep(10)) end
	a = blake2b.final(ctx)
	assert(a == b)
	--
	ctx = blake2b.init()
	for _ = 1, 1000 do blake2b.update(ctx, 'a') end
	a = blake2b.final(ctx)
	assert(a == b)
	--
	-- test shorter digest
	a = blake2b.hash("abc", 32)
	b = hextos[[
	bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319 ]]
	assert(a == b)
	--
	a = blake2b.hash("abc", 7)
	b = hextos[[ d5355e84cd8e92 ]]
	assert(a == b)
	--
	-- test keyed digest
	a = blake2b.hash("abc", 64, "key key key")
	b = hextos[[
	cd63b5bfd9d74769c604fc5e1b4d0486078511abc07ab748e6ae0e2654058354
	df6651c28d31396c71837d483fd1d1c5f9331fb23323495a6868361ad8196221 ]]
	assert(a == b)
	--
end --test_blake2b()


test_blake2b()

print("test_blake2b: ok")
