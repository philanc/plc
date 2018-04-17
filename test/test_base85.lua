-- Copyright (c) 2017  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------
-- base85 (Z85) tests

z85 = require("plc.base85")

local s, m, e, s2, st

-- test string from https://rfc.zeromq.org/spec:32/Z85/
s = "\x86\x4F\xD2\x6F\xB5\x59\xF7\x5B"
e = z85.encode(s)
assert(e == "HelloWorld")

s2 = z85.decode(e)
assert(s2 == s)

-- test string from https://github.com/zeromq/rfc/blob/master/src/spec_32.c
s =     "\x8E\x0B\xDD\x69\x76\x28\xB9\x1D" ..
        "\x8F\x24\x55\x87\xEE\x95\xC5\xB0" ..
        "\x4D\x48\x96\x3F\x79\x25\x98\x77" .. 
        "\xB4\x9C\xD9\x06\x3A\xEA\xD3\xB7"  
e = z85.encode(s)
assert(e == "JTKVSB%%)wK0E.X)V>+}o?pNmC{O&4W4b!Ni{Lh6")
s2 = z85.decode(e)
assert(s2 == s)

s, m = z85.decode"abc"
assert(not s and m == "invalid length")
s, m = z85.decode[[abc"']]
assert(not s and m == "invalid char")

print("test_base85: ok")
