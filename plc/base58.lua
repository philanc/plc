-- Copyright (c) 2015  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------
--[[

base58 encode/decode functions

Usual Base58 alphabets: (see wikipedia)
Bitcoin address  123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
Ripple address   rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz
Flick short URL  123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ

The alphabet used in this module is the Bitcoin adress encoding alphabet:
	123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz

Note:
Base58 encoding, contrary to Base64, is not intended to encode long
strings. Base64 can encode long strings 3 bytes at a time.
On the contrary, Base58 treats the string to be encoded as a long number
encoded in Base256 (each byte is a digit) and perform an arithmetic
conversion of this long number to base58.


]]


local byte, char, concat = string.byte, string.char, table.concat

local b58chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

local function encode(s)
	local q, b
	local et = {}
	local zn = 0 	-- number of leading zero bytes in s
	-- assume s is a large, little-endian binary number
	-- with base256 digits (each byte is a "digit")
	local nt = {} -- number to divide in base 256, big endian
	local dt = {} -- result of nt // 58, in base 256
	local more = true  -- used to count leading zero bytes
	for i = 1, #s do
		b = byte(s, i)
		if more and b == 0 then
			zn = zn + 1
		else
			more = false
		end
		nt[i] = b
	end
	if #s == zn then --take care of strings empty or with only nul bytes
		return string.rep('1', zn)
	end
	more = true
	while more do
		local r = 0
		more = false
		for i = 1, #nt do
			b = nt[i] + (256 * r)
			q = b // 58
			-- if q is not null at least once, we are good
			-- for another division by 58
			more = more or q > 0
			r = b % 58
			dt[i] = q
		end
		-- r is the next base58 digit. insert it before previous ones
		-- to get a big-endian base58 number
		table.insert(et, 1, char(byte(b58chars, r+1)))
		-- now copy dt into nt before another round of division by 58
		nt = {}
		for i = 1, #dt do nt[i] = dt[i] end
		dt = {}
	end--while
	-- don't forget the leading zeros ('1' is digit 0 in bitcoin base58 alphabet)
	return string.rep('1', zn) .. concat(et)
end --encode()

-- inverse base58 map, used by b58decode:  b58charmap maps characters in
-- base58 alphabet to their _offset_ in b58chars (0-based, not 1-based...)
--  eg.	for digit '1' b64charmap[65] == 0  and for 'z', b64charmap[122] == 57
--
local b58charmap = {};
for i = 1, 58 do b58charmap[byte(b58chars, i)] = i - 1  end

local function decode(s)
	-- reject invalid encoded strings
	if string.find(s, "[^"..b58chars.."]") then
		return nil, "invalid char"
	end
	-- process leading zeros - count and remove them
	local zn -- number of leading zeros (base58 digits '1')
	zn = #(string.match(s, "^(1+)") or "")
	s = string.gsub(s, "^(1+)", "")
	-- special case: the string is empty or contains only null bytes
	if s == "" then
		return string.rep('\x00', zn)
	end
	--
	-- process significant digits
	local dn -- decoded number as an array of bytes (little-endian)
	local d -- base58 digit, as an integer
	local b -- a byte in dn
	local m -- a byte multiplied by 58 (used for product)
	local carry
	dn = { b58charmap[byte(s, 1)] } --init with most significant digit
	for i = 2, #s do --repeat until no more digits
		-- multiply dn by 58, then add next digit
		d = b58charmap[byte(s, i)] -- next digit
		carry = 0
		-- multiply dn by 58
		for j = 1, #dn do
			b = dn[j]
			m = b * 58 + carry
			b = m & 0xff
			carry = m >> 8
			dn[j] = b
		end
		if carry > 0 then dn[#dn + 1] = carry end
		-- add next digit to dn
		carry = d
		for j = 1, #dn do
			b = dn[j] + carry
			carry = b >> 8
			dn[j] = b & 0xff
		end
		if carry > 0 then dn[#dn + 1] = carry end
	end
	-- now dn contains the decoded number (little endian)
	-- must add leading zeros and reverse dn to build binary string
	local ben = {} -- big-endian number as array of chars
	local ln = #dn
	for i = 1, ln do
		ben[i] = char(dn[ln-i+1])
	end
	return string.rep('\x00', zn) .. concat(ben)
end --decode()


return { -- base58 module
	encode = encode,
	decode = decode,
	}
