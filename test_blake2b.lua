-- Copyright (c) 2017 Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------
-- blake2b tests

local blake2b = require 'blake2b'

local bin = require 'bin'  -- for hex conversion

local stohex, hextos = bin.stohex, bin.hextos

------------------------------------------------------------------------
--~ lz=require'lz'
--~ s = ('a'):rep(1000)
--~ print(stohex(lz.blake2b(s), 32))

local function test_blake2b()
	local a, b
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
	local ctx
	ctx = blake2b.init()
	blake2b.update(ctx, ('a'):rep(500))
	blake2b.update(ctx, ('a'):rep(500))
	a = blake2b.final(ctx)
	assert(a == b)
	--
	ctx = blake2b.init()
	for i = 1, 100 do blake2b.update(ctx, ('a'):rep(10)) end
	a = blake2b.final(ctx)
	assert(a == b)
	--
	
end


test_blake2b()

print("test_blake2b: ok")
