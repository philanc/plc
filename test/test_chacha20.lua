-- Copyright (c) 2015  Phil Leblanc  -- see LICENSE file
------------------------------------------------------------

-- test chacha20.lua


local chacha20 = require "plc.chacha20"

local bin = require "plc.bin"
local stx, xts = bin.stohex, bin.hextos

------------------------------------------------------------

local function test_chacha20_encrypt()
	-- quick test with RFC 7539 test vector
	local plain =
		"Ladies and Gentlemen of the class of '99: If I could "
	..	"offer you only one tip for the future, sunscreen would be it."
	local key =
		"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
	..	"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
	local nonce = "\x00\x00\x00\x00\x00\x00\x00\x4a\x00\x00\x00\x00"
	assert(#key == chacha20.key_size)
	assert(#nonce == chacha20.nonce_size)
	local counter = 1
	local expected =
	   "\x6e\x2e\x35\x9a\x25\x68\xf9\x80\x41\xba\x07\x28\xdd\x0d\x69\x81"
	.. "\xe9\x7e\x7a\xec\x1d\x43\x60\xc2\x0a\x27\xaf\xcc\xfd\x9f\xae\x0b"
	.. "\xf9\x1b\x65\xc5\x52\x47\x33\xab\x8f\x59\x3d\xab\xcd\x62\xb3\x57"
	.. "\x16\x39\xd6\x24\xe6\x51\x52\xab\x8f\x53\x0c\x35\x9f\x08\x61\xd8"
	.. "\x07\xca\x0d\xbf\x50\x0d\x6a\x61\x56\xa3\x8e\x08\x8a\x22\xb6\x5e"
	.. "\x52\xbc\x51\x4d\x16\xcc\xf8\x06\x81\x8c\xe9\x1a\xb7\x79\x37\x36"
	.. "\x5a\xf9\x0b\xbf\x74\xa3\x5b\xe6\xb4\x0b\x8e\xed\xf2\x78\x5e\x42"
	.. "\x87\x4d"
	local et = chacha20.encrypt(key, counter, nonce, plain)
	-- px(et)
	assert(et == expected)
	assert(plain == chacha20.encrypt(key, counter, nonce, et))
	--
	-- test some input lengths
	for i = 1, 66 do
		plain = ('p'):rep(i)
		et = chacha20.encrypt(key, counter, nonce, plain)
		local dt = chacha20.decrypt(key, counter, nonce, et)
		assert((#et == #plain) and (dt == plain))
	end
	--
	return true
end

test_chacha20_encrypt()

print("test_chacha20: ok")
