-- Copyright (c) 2015  Phil Leblanc  -- see LICENSE file
------------------------------------------------------------------------

-- base64 encode / decode

local byte, char, concat = string.byte, string.char, table.concat

local B64CHARS = 	-- Base64 alphabet (RFC 4648)
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

-- inverse base64 map, used by b64decode:  b64charmap maps characters in
-- base64 alphabet to their _offset_ in b64chars (0-based, not 1-based...)
--  eg.	for 'A' b64charmap[65] == 0  and for '/', b64charmap[47] == 63
--
local b64charmap = {};
for i = 1, 64 do b64charmap[byte(B64CHARS, i)] = i - 1  end

-- filename-safe alphabet (RFC 4648):
-- '+/' are respectively replaced with '-_'

local function encode(s, filename_safe)
	-- encode binary string s. returns base64 encoded string
	-- correct padding ('=') is appended to encoded string
	-- if the encoded string is longer than 72,
	-- a newline is added every 72 chars.
	-- if optional argument filename_safe is true, '+/' are replaced
	-- with '-_' in encoded string and padding and newlines are removed
	local b64chars = B64CHARS
	local rn = #s % 3
	local st = {}
	local c1, c2, c3
	local t4 = {}
	local lln, maxlln = 1, 72
	for i = 1, #s, 3 do
		c1 = byte(s,i)
		c2 = byte(s,i+1) or 0
		c3 = byte(s,i+2) or 0
		t4[1] = char(byte(b64chars, (c1 >> 2) + 1))
		t4[2] = char(byte(b64chars, (((c1 << 4)|(c2 >> 4)) & 0x3f) + 1))
		t4[3] = char(byte(b64chars, (((c2 << 2)|(c3 >> 6)) & 0x3f) + 1))
		t4[4] = char(byte(b64chars, (c3 & 0x3f) + 1))
		st[#st+1] = concat(t4)
		-- insert a newline every 72 chars of encoded string
		lln = lln + 4
		if lln > maxlln then st[#st+1] = "\n"; lln = 1 end
	end
	-- process remaining bytes and padding
	local llx = #st  -- index of last st element with data
	if st[llx] == "\n" then llx = llx - 1 end 
	if rn == 2 then
		st[llx] = string.gsub(st[llx], ".$", "=")
	elseif rn == 1 then
		st[llx] = string.gsub(st[llx], "..$", "==")
	end
	local b = concat(st)
	if filename_safe then
		-- assume that filename safe mode is not used for very long
		-- strings. Making 3 copies below is not considered an issue.
		b = string.gsub(b, "%+", "-")
		b = string.gsub(b, "/", "_")
		b = string.gsub(b, "[%s=]", "")
	end
	return b
end --encode

local function decode(b)
	-- decode base64-encoded string
	-- ignore all whitespaces, newlines, and padding ('=') in b
	local cmap = b64charmap
	local e1, e2, e3, e4
	local st = {}
	local t3 = {}
	b = string.gsub(b, "%-", "+")
	b = string.gsub(b, "_", "/")
	b = string.gsub(b, "[=%s]", "") -- remove all whitespaces and '='
	if b:find("[^0-9A-Za-z/+=]") then return nil, "invalid char" end
	for i = 1, #b, 4 do
		e1 = cmap[byte(b, i)]
		e2 = cmap[byte(b, i+1)]
		if not e1 or not e2 then return nil, "invalid length" end
		e3 = cmap[byte(b, i+2)]
		e4 = cmap[byte(b, i+3)]
		t3[1] = char((e1 << 2) |  (e2 >> 4))
		if not e3 then
			t3[2] = nil
			t3[3] = nil
			st[#st + 1] = concat(t3)
			break
		end
		t3[2] = char(((e2 << 4) | (e3 >> 2)) & 0xff)
		if not e4 then
			t3[3] = nil
			st[#st + 1] = concat(t3)
			break
		end
		t3[3] = char(((e3 << 6) | (e4)) & 0xff)
		st[#st + 1] = concat(t3)
	end --for
	return concat(st)
end --decode


return  {
	-- base64 module
	encode = encode,
	decode = decode,
	}
