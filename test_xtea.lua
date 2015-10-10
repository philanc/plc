-- Copyright (c) 2015  Phil Leblanc  -- see LICENSE file
------------------------------------------------------------

-- test xtea.lua


local xtea = require "xtea"

local bin = require"bin"
local stx = bin.stohex
local xts = bin.hextos
local function px(s) print(stx(s, 16, " ")) end
local function pf(...) print(string.format(...)) end

local spack, sunpack = string.pack, string.unpack
local app, concat = table.insert, table.concat


------------------------------------------------------------

local function test_xtea()
	local k1 = xts"000102030405060708090a0b0c0d0e0f"
	local k0 = xts"00000000000000000000000000000000"
	local st0 = xtea.keysetup(k0)
	local st1 = xtea.keysetup(k1)
	local p, e, pu, eu
	--
	p = xts"4142434445464748"; pu = sunpack('>I8', p)
	e = xts"497df3d072612cb5"; eu = sunpack('>I8', e)
	assert(xtea.encryptblock(st1, p) == e)
	assert(xtea.encryptu64(st1, pu) == eu)
	assert(xtea.decryptblock(st1, e) == p)
	assert(xtea.decryptu64(st1, eu) == pu)
	--
	p = xts"4142434445464748"; pu = sunpack('>I8', p)
	e = xts"a0390589f8b8efa5"; eu = sunpack('>I8', e)
	assert(xtea.encryptblock(st0, p) == e)
	assert(xtea.encryptu64(st0, pu) == eu)
	assert(xtea.decryptblock(st0, e) == p)
	assert(xtea.decryptu64(st0, eu) == pu)
	
	
	return true
end

test_xtea()

print("test_xtea: ok")
