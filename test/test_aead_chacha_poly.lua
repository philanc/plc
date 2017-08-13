-- Copyright (c) 2015  Phil Leblanc  -- see LICENSE file
------------------------------------------------------------

local aead = require "plc.aead_chacha_poly"


local function test_aead_encrypt()
--
-- test poly_keygen()  -- rfc, sect 2.6.2
--
local key, nonce, expected, aad, iv, const, plain, exptag, encr, res, tag
key = "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
.. "\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
nonce = "\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07"
expected = "\x8a\xd5\xa0\x8b\x90\x5f\x81\xcc\x81\x50\x40\x27\x4a\xb2\x94\x71"
.. "\xa8\x33\xb6\x37\xe3\xfd\x0d\xa5\x08\xdb\xb8\xe2\xfd\xd1\xa6\x46"
assert(aead.poly_keygen(key, nonce) == expected)
--
-- test aead_encrypt()  -- rfc, sect 2.8.2
--
key = "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
.. "\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
aad = "\x50\x51\x52\x53\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7"
iv = "\x40\x41\x42\x43\x44\x45\x46\x47"
const = "\x07\x00\x00\x00"
plain = "Ladies and Gentlemen of the class of '99: If I could offer you only "
    .. "one tip for the future, sunscreen would be it."
exptag = "\x1a\xe1\x0b\x59\x4f\x09\xe2\x6a\x7e\x90\x2e\xcb\xd0\x60\x06\x91"
encr, tag = aead.encrypt(aad, key, iv, const, plain)
assert(#plain == #encr)
assert( tag == exptag )
res = aead.decrypt(aad, key, iv, const, encr, tag)
assert(res == plain)
--
end -- test_aead_encrypt()


test_aead_encrypt()
print("test_aead_encrypt: ok")
