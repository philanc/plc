-- Copyright (c) 2017  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------
-- gimli tests

local bin = require "plc.bin"
local xts = bin.hextos

gim = require "plc.gimli"

local function px12(st) 
	local fmt = "%08x %08x %08x %08x \n"
		.. "%08x %08x %08x %08x \n"
		.. "%08x %08x %08x %08x \n"
		.. "-----------------------------------"
	print(string.format(fmt, 
		st[1], st[2], st[3], st[4],
		st[5], st[6], st[7], st[8],
		st[9], st[10], st[11], st[12]))
end

-- core permutation test
st = {} -- permutation state (12 32-byte integers)
-- initialize the state 
-- see gimli-20170627/test.c in the reference implementation 
-- at https://gimli.cr.yp.to/
for i = 0, 11 do 
	st[i+1] = (i * i * i + i * 0x9e3779b9) & 0xffffffff 
end
--~ px12(st)
gim.gimli_core32(st)
--~ px12(st)
local expected = {
	0xba11c85a, 0x91bad119, 0x380ce880, 0xd24c2c68, 
	0x3eceffea, 0x277a921c, 0x4f73a0bd, 0xda5a9cd8, 
	0x84b673f0, 0x34e52ff7, 0x9e2bef49, 0xf41bb8d6
}
for i = 1, 12 do assert(st[i] == expected[i]) end 


print("test_gimli: ok")
