-- Copyright (c) 2018  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------
--[[

=== z85 - the ZeroMQ variant of Ascii85 encoding

Ascii85 encodes binary strings by using five displayable ascii characters 
to represent 4 bytes of data.

The Z85 encoding alphabet is designed to facilitate embedding encoded 
strings in source code or scripts (eg. double-quote, single-quote, 
backslash are not used).

Specification: https://rfc.zeromq.org/spec:32/Z85/

The Z85 specification makes no provision for padding. The application
must ensure that the length of the string to encode is a multiple of 4.

TODO(?):  add an option to use the RFC 1924 [1] alphabet
which is maybe better because "This character set excludes the 
characters "',./:[\] , making it suitable for use in JSON strings" [2]

[1] https://tools.ietf.org/html/rfc1924
[2] https://en.wikipedia.org/wiki/Ascii85


Note: the original Ascii85/btoa will not be implemented. The alphabet is 
less convenient that the two variants above, and the special characters 
for groups of 4 NULs or 4 spaces are not useful for compressed 
and/or encrypted data. 

]]

local spack, sunpack = string.pack, string.unpack
local byte, char = string.byte, string.char
local insert, concat = table.insert, table.concat

-- Z85 alphabet - see https://rfc.zeromq.org/spec:32/Z85/
local chars =  
	"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	.. ".-:+=^!/*?&<>()[]{}@%$#"

local inv = {} -- maps base85 digit ascii representation to their value
for i = 1, #chars do inv[byte(chars, i)] = i - 1 end

local function encode(s)
	local n, r1, r2, r3, r4, r5
	-- #s must be multiple of 4 bytes
	assert(#s % 4 == 0, "string length must be multiple of 4 bytes")
	local et = {} -- used to collect encoded blocks of 4 bytes
	for i = 1, #s, 4 do
		n = sunpack(">I4", s, i)
--~ 		print(i, n)
		r5 = n % 85 ; n = n // 85
		r4 = n % 85 ; n = n // 85
		r3 = n % 85 ; n = n // 85
		r2 = n % 85 ; n = n // 85
		r1 = n % 85 ; n = n // 85
		local eb = char(
			chars:byte(r1 + 1),
			chars:byte(r2 + 1),
			chars:byte(r3 + 1),
			chars:byte(r4 + 1),
			chars:byte(r5 + 1))
		insert(et, eb)
	end--for
	return table.concat(et)
end

local function decode(e)
	local st = {}  -- used to collect decoded blocks of 4 bytes
	local n, r1, r2, r3, r4, r5
	if #e % 5 ~= 0 then 
		-- encoded length must be multiple of 5 bytes
		return nil, "invalid length" 
	end
	for i = 1, #e, 5 do
		n = 0
		for j = 0, 4 do
			r = inv[e:byte(i+j)]
			if not r then 
				return nil, "invalid char"
			end
			n = n * 85 + r
		end
		local sb = spack(">I4", n)
		insert(st, sb)
	end--for
	return table.concat(st)
end

local z85 = {
	encode = encode,
	decode = decode,
}

return z85



