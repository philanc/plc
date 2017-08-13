-- Copyright (c) 2015  Phil Leblanc  -- see LICENSE file
------------------------------------------------------------------------

-- test bin.lua

local bin = require "plc.bin"

local stx = bin.stohex
local xts = bin.hextos

------------------------------------------------------------------------

local function test_bin()
	local e
	--
	-- test hex / string conversion
	local s13 = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d"
	local s26 = s13 .. s13
	assert(stx(s13) == "0102030405060708090a0b0c0d")
	assert(stx(s13, 16) == "0102030405060708090a0b0c0d")
	assert(stx(s13, 16, ':') == "01:02:03:04:05:06:07:08:09:0a:0b:0c:0d")
	assert(stx(s26) ==
		"0102030405060708090a0b0c0d0102030405060708090a0b0c0d")
	assert(stx(s26, 16) ==
		"0102030405060708090a0b0c0d010203\n0405060708090a0b0c0d")
	assert(stx(s26, 16, '+') ==
		"01+02+03+04+05+06+07+08+09+0a+0b+0c+0d+" ..
		"01+02+03\n04+05+06+07+08+09+0a+0b+0c+0d" )
	--
	assert(xts("0102030405060708090a0b0c0d") == s13)
	-- ignore whitespace
	assert(xts("  01020304050 \n 6070\t8090a0 b 0 c0d\n") == s13)
	-- with unsafe=true, invalid chars and whitespace are NOT ignored...
	assert(xts("01 02 030405060708090a0b0c0d", true) ~= s13)
	-- error cases
	--   (invalid chars)
	assert(not pcall(xts, "!!!  0102030405060708090a0b0c0d"))
	--   (invalid length, after whitespace removal)
	assert(not pcall(xts, "abc "))
	--
	-- test xor
	local pa5 = ('\xaa\x55'):rep(8)
	local p5a = ('\x55\xaa'):rep(8)
	local p00 = ('\x00\x00'):rep(8)
	local pff = ('\xff\xff'):rep(8)
	assert(bin.xor1(pa5, p00) == pa5)
	assert(bin.xor1(pa5, pff) == p5a)
	assert(bin.xor1(pa5, pa5) == p00)
	assert(bin.xor1(pa5, p5a) == pff)
	--
	assert(bin.xor8(pa5, p00) == pa5)
	assert(bin.xor8(pa5, pff) == p5a)
	assert(bin.xor8(pa5, pa5) == p00)
	assert(bin.xor8(pa5, p5a) == pff)
	--
	local function test_xor(xorfn, k, p)
		e = xorfn(k, p)
		--px(e)
		assert(#e == #p)
		assert(xorfn(k, e) == p)
	end
	test_xor(bin.xor1, ("k"):rep(1), ("a"):rep(1))
	test_xor(bin.xor1, ("k"):rep(1), ("a"):rep(7))
	test_xor(bin.xor1, ("k"):rep(3), ("a"):rep(8))
	test_xor(bin.xor1, ("k"):rep(9), ("a"):rep(31))
	test_xor(bin.xor1, ("k"):rep(1), ("a"):rep(7))
	test_xor(bin.xor1, ("k"):rep(1), ("a"):rep(7))

	test_xor(bin.xor8, ("k"):rep(8), ("a"):rep(1))
	test_xor(bin.xor8, ("k"):rep(8), ("a"):rep(7))
	test_xor(bin.xor8, ("k"):rep(8), ("a"):rep(8))
	test_xor(bin.xor8, ("k"):rep(8), ("a"):rep(31))
	test_xor(bin.xor8, ("k"):rep(16), ("a"):rep(7))
	test_xor(bin.xor8, ("k"):rep(32), ("a"):rep(71))
	--
	return true
end

test_bin()

print("test_bin: ok")
