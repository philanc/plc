-- Copyright (c) 2015  Phil Leblanc  -- see LICENSE file
------------------------------------------------------------------------
--[[

Rabbit stream cipher

Rabbit was one of the four eSTREAM finalists in 2008
(for profile 1 -- sofware implementation)
http://www.ecrypt.eu.org/stream/endofphase3.html

Rabbit presentation pages at eSTREAM and at ECRYPT II
http://www.ecrypt.eu.org/stream/rabbitpf.html
http://www.ecrypt.eu.org/stream/e2-rabbit.html

Rabbit was also specified in RFC 4503
http://www.ietf.org/rfc/rfc4503.txt

Released into the public domain in 2008.
http://www.ecrypt.eu.org/stream/phase3ip.html#rabbit

See also:

Presentation paper
http://www.ecrypt.eu.org/stream/p3ciphers/rabbit/rabbit_p3.pdf

Performance
http://www.ecrypt.eu.org/stream/perf/pentium-m/

Wikipedia page
https://en.wikipedia.org/wiki/Rabbit_%28cipher%29

Ecrypt2 report on algorithms and key sizes
http://www.ecrypt.eu.org/ecrypt2/


]]

------------------------------------------------------------------------

local spack, sunpack = string.pack, string.unpack
local app, concat = table.insert, table.concat

local function rotl32(i, n)
	-- rotate left on 32 bits
	return ((i << n) | (i >> (32 - n))) & 0xffffffff
end

------------------------------------------------------------------------

local function gfunc(x)
	-- square a 32-bit unsigned integer
	-- return the upper 32 bits xor the lower 32 bits of the result
	local h = x * x
	-- looks like the mult works for arbitrary uint32 x...
	-- normal or happy impl detail?
	local l = h & 0xffffffff
	h = h >> 32  --logical shift: no sign extension => clean uint32
	return h ~ l
end --gfunc

local function newstate()
	-- return a new, empty state
	return {
		x = {0,0,0,0,0,0,0,0},  -- 8 * u32
		c = {0,0,0,0,0,0,0,0},  -- 8 * u32
		co = {0,0,0,0,0,0,0,0},  -- 8 * u32
		g = {0,0,0,0,0,0,0,0},  -- 8 * u32
		-- (co is "c_old" in reference impl.
		--  co and g are kept in state to
		--  prevent reallocation at every invocation)
		carry = 0  -- u32
	}
end --newstate

local function clonestate(st)
	-- return a copy of state st
	-- (allows to keep a "master" state for a same key setup
	--  and create "working" states for different IV)
	local nst = newstate()
	for i = 1, 8 do
		nst.x[i] = st.x[i]
		nst.c[i] = st.c[i]
	end
	nst.carry = st.carry
	return nst
end --clonestate

local function nextstate(st)
	local x, c, co, g = st.x, st.c, st.co, st.g
	local rl = rotl32
	for i = 1, 8 do  co[i] = c[i]  end
	-- compute new counter values
	c[1] = (c[1] + 0x4D34D34D + st.carry) & 0xffffffff
	c[2] = (c[2] + 0xD34D34D3 + (c[1] < co[1] and 1 or 0)) & 0xffffffff
	c[3] = (c[3] + 0x34D34D34 + (c[2] < co[2] and 1 or 0)) & 0xffffffff
	c[4] = (c[4] + 0x4D34D34D + (c[3] < co[3] and 1 or 0)) & 0xffffffff
	c[5] = (c[5] + 0xD34D34D3 + (c[4] < co[4] and 1 or 0)) & 0xffffffff
	c[6] = (c[6] + 0x34D34D34 + (c[5] < co[5] and 1 or 0)) & 0xffffffff
	c[7] = (c[7] + 0x4D34D34D + (c[6] < co[6] and 1 or 0)) & 0xffffffff
	c[8] = (c[8] + 0xD34D34D3 + (c[7] < co[7] and 1 or 0)) & 0xffffffff
	st.carry = c[8] < co[8] and 1 or 0
	-- compute the g-values
	for i = 1, 8 do g[i] = gfunc((x[i] + c[i]) & 0xffffffff) end
	-- compute new state values (don't forget arrays are 1-based!!)
	x[1] = (g[1] + rl(g[8],16) + rl(g[7],16)) & 0xffffffff
	x[2] = (g[2] + rl(g[1],8) + g[8]) & 0xffffffff
	x[3] = (g[3] + rl(g[2],16) + rl(g[1],16)) & 0xffffffff
	x[4] = (g[4] + rl(g[3],8) + g[2]) & 0xffffffff
	x[5] = (g[5] + rl(g[4],16) + rl(g[3],16)) & 0xffffffff
	x[6] = (g[6] + rl(g[5],8) + g[4]) & 0xffffffff
	x[7] = (g[7] + rl(g[6],16) + rl(g[5],16)) & 0xffffffff
	x[8] = (g[8] + rl(g[7],8) + g[6]) & 0xffffffff
	-- done
end --nextstate

local function keysetup(st, key)
	-- key is a 16 byte string
	assert(#key == 16)
	local k1, k2, k3, k4 = sunpack("<I4I4I4I4", key)
	local x, c = st.x, st.c
	-- initial state variables
	x[1] = k1
	x[3] = k2
	x[5] = k3
	x[7] = k4
	x[2] = ((k4<<16) & 0xffffffff | (k3>>16))
	x[4] = ((k1<<16) & 0xffffffff | (k4>>16))
	x[6] = ((k2<<16) & 0xffffffff | (k1>>16))
	x[8] = ((k3<<16) & 0xffffffff | (k2>>16))
	-- initial counter values
	c[1] = rotl32(k3, 16)
	c[3] = rotl32(k4, 16)
	c[5] = rotl32(k1, 16)
	c[7] = rotl32(k2, 16)
	c[2] = (k1 & 0xffff0000) | (k2 & 0xffff)
	c[4] = (k2 & 0xffff0000) | (k3 & 0xffff)
	c[6] = (k3 & 0xffff0000) | (k4 & 0xffff)
	c[8] = (k4 & 0xffff0000) | (k1 & 0xffff)
	--
	st.carry = 0
	-- iterate 4 times
	for _ = 1, 4 do
		nextstate(st)
	end
	-- modify the counters
	for i = 1, 4 do c[i] = c[i] ~ x[i+4] end
	for i = 5, 8 do c[i] = c[i] ~ x[i-4] end
end

local function ivsetup(st, iv)
	-- iv is an 8-byte string
	--
	assert(#iv == 8)
	local i1, i2, i3, i4
	i1, i3 = sunpack("<I4I4", iv)
	i2 = (i1 >> 16) | (i3 & 0xffff0000)
	i4 = (i3 << 16) & 0xffffffff | (i1 & 0x0000ffff)
	-- modify counter values
	local c = st.c
	c[1] = c[1] ~ i1
	c[2] = c[2] ~ i2
	c[3] = c[3] ~ i3
	c[4] = c[4] ~ i4
	c[5] = c[5] ~ i1
	c[6] = c[6] ~ i2
	c[7] = c[7] ~ i3
	c[8] = c[8] ~ i4
	-- iterate 4 times
	for _ = 1, 4 do  nextstate(st)  end
	-- done
end --ivsetup

local function processblock(st, itxt, idx)
	-- itxt is the input string, idx is an index in itxt
	-- processblock encrypts/decrypts one block, ie. 16 bytes in itxt
	-- processblock returns the result as a string and a flag set to true
	-- if this was the last block in itxt (ie. #itxt - idx <= 16)
	--
	local i1, i2, i3, i4 	-- input, as 4 uint32 words
	local o1, o2, o3, o4	-- output, as 4 uint32 words
	-- bn: byte number (used for a last, incomplete block)
	local bn = #itxt - idx + 1
	local last = bn <= 16	-- last block in itxt
	local short = bn < 16   -- last block, shorter than 16 bytes
	local fmt = "<I4I4I4I4" -- format to unpack 16 bytes as 4 uint32
	if short then
		local buffer = string.sub(itxt, idx) .. string.rep('\0', 16 - bn)
		itxt = buffer
		idx = 1
	end
	i1, i2, i3, i4 = sunpack(fmt, itxt, idx)
	nextstate(st)
	local x = st.x
	o1 = i1 ~ x[1] ~ (x[6] >> 16) ~ ((x[4] << 16) & 0xffffffff)
	o2 = i2 ~ x[3] ~ (x[8] >> 16) ~ ((x[6] << 16) & 0xffffffff)
	o3 = i3 ~ x[5] ~ (x[2] >> 16) ~ ((x[8] << 16) & 0xffffffff)
	o4 = i4 ~ x[7] ~ (x[4] >> 16) ~ ((x[2] << 16) & 0xffffffff)
	local outstr = spack(fmt, o1, o2, o3, o4)
	if short then
		outstr = string.sub(outstr, 1, bn)
	end
	return outstr, last
end --processblock

local function crypt(key, iv, text)
	-- encrypt/decrypt a text (this is the main API of the module)
	-- key is a 16-byte string
	-- iv is a 8-byte string
	-- text is the text to encrypt/decrypt
	-- returns the encrypted/decrypted text
	local st = newstate()
	keysetup(st, key)
	ivsetup(st, iv)
	if #text == 0 then return "" end
	local ot = {}  -- a table to collect output
	local ob, last  -- output block, last block flag
	local idx = 1
	repeat
		ob, last = processblock(st, text, idx)
		idx = idx + 16 --next block
		app(ot, ob)
	until last
	return concat(ot)
end --crypt


------------------------------------------------------------------------
return { -- rabbit module
	encrypt = crypt,
	decrypt = crypt,
	--
	key_size = 16,
	iv_size = 8,
	--
	-- functions for more complex scenarios
	newstate = newstate,
	clonestate = clonestate,
	keysetup = keysetup,
	ivsetup = ivsetup,
	processblock = processblock,
}

