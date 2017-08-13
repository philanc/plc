-- Copyright (c) 2015  Phil Leblanc  -- see LICENSE file
------------------------------------------------------------------------

-- test xtea.lua


local xtea = require "plc.xtea"

local bin = require "plc.bin"
local stx = bin.stohex
local xts = bin.hextos
local function px(s) print(stx(s, 16, " ")) end
local function pf(...) print(string.format(...)) end

local spack, sunpack = string.pack, string.unpack
local app, concat = table.insert, table.concat

------------------------------------------------------------------------

local function test_xtea()
	--
	-- test core XTEA functions
	local k1 = xts"000102030405060708090a0b0c0d0e0f"
	local k0 = xts"00000000000000000000000000000000"
	local st0 = xtea.keysetup(k0)
	local st1 = xtea.keysetup(k1)
	local p, e, pu, eu, iv
	--
	p = xts"4142434445464748"; pu = sunpack('>I8', p)
	e = xts"497df3d072612cb5"; eu = sunpack('>I8', e)
	assert(xtea.encrypt_s8(st1, p) == e)
	assert(xtea.encrypt_u64(st1, pu) == eu)
	assert(xtea.decrypt_s8(st1, e) == p)
	assert(xtea.decrypt_u64(st1, eu) == pu)
	--
	p = xts"4142434445464748"; pu = sunpack('>I8', p)
	e = xts"a0390589f8b8efa5"; eu = sunpack('>I8', e)
	assert(xtea.encrypt_s8(st0, p) == e)
	assert(xtea.encrypt_u64(st0, pu) == eu)
	assert(xtea.decrypt_s8(st0, e) == p)
	assert(xtea.decrypt_u64(st0, eu) == pu)
	--
	-- test stream encryption
	iv = "12345678"
	local function test_ctr(p)
		e = xtea.encrypt(k1, iv, p)
		--px(e)
		assert(#e == #p)
		assert(xtea.decrypt(k1, iv, e) == p)
	end
	test_ctr""
	test_ctr"a"
	test_ctr(("a"):rep(7))
	test_ctr(("a"):rep(8))
	test_ctr(("a"):rep(9))
	test_ctr(("a"):rep(15))
	test_ctr(("a"):rep(100))

	return true
end

test_xtea()

print("test_xtea: ok")
