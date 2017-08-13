-- Copyright (c) 2015  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------
-- rc4 encryption / decryption

local byte, char, concat = string.byte, string.char, table.concat

--[[

(RC4 pseudo code, from wikipedia)

 key scheduling --  keylength in [1..256] bytes, typically 16 (128 bits)
	 for i from 0 to 255
	    S[i] := i
	endfor
	j := 0
	for i from 0 to 255
	    j := (j + S[i] + key[i mod keylength]) mod 256
	    swap values of S[i] and S[j]
	endfor

Pseudo-random generation
	i := 0
	j := 0
	while GeneratingOutput:
	    i := (i + 1) mod 256
	    j := (j + S[i]) mod 256
	    swap values of S[i] and S[j]
	    K := S[(S[i] + S[j]) mod 256]
	    output K
	endwhile

]]

local function keysched(key)
	-- key must be a 16-byte string
	assert(#key == 16)
	local s = {}
	local j,ii,jj
	for i = 0, 255 do s[i+1] = i end
	j = 0
	for i = 0, 255 do
		ii = i+1
		j = (j + s[ii] + byte(key, (i % 16) + 1)) & 0xff
		jj = j+1
		s[ii], s[jj] = s[jj], s[ii]
	end
	return s
end

local function step(s, i, j)
	i = (i + 1) & 0xff
	local ii = i + 1
	j = (j + s[ii]) & 0xff
	local jj = j + 1
	s[ii], s[jj] = s[jj], s[ii]
	local k = s[ ((s[ii] + s[jj]) & 0xff) + 1 ]
	return s, i, j, k
end

local function rc4raw(key, plain)
	-- raw encryption
	-- key must be a 16-byte string
	local s = keysched(key)
	local i, j = 0, 0
	local k
	local t = {}
	for n = 1, #plain do
		s, i, j, k = step(s, i, j)
		t[n] = char(byte(plain, n) ~ k)
	end
	return concat(t)
end

local function rc4(key, plain, drop)
	-- encrypt 'plain', return encrypted text
	-- key must be a 16-byte string
	-- optional drop (default = 256): ignore first 'drop' iterations
	drop = drop or 256
	local s = keysched(key)
	local i, j = 0, 0
	local k
	local t = {}
	-- run and ignore 'drop' iterations
	for _ = 1, drop do
		s, i, j = step(s, i, j)
	end
	-- now start to encrypt
	for n = 1, #plain do
		s, i, j, k = step(s, i, j)
		t[n] = char(byte(plain, n) ~ k)
	end
	return concat(t)
end

return 	{ -- module
	rc4raw = rc4raw,
	rc4 = rc4,
	encrypt = rc4,
	decrypt = rc4,
	}
