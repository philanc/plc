package = "plc"
version = "0.5-1"

source = {
    url = "git://github.com/philanc/plc.git",
    branch = "v0.5",
}

description = {
    summary = "Pure Lua Crypto",
    detailed = [[
        A pure Lua cryptograhy library (Authenticated encryption: NORX,
		NaCl secretbox, Chach20+Poly1305. Public key encryption: NaCl box,
		ec25519 scalar multiplication. Encryption: NORX, Chacha20, Salsa20,
		Rabbit, XTea, RC4. Hash: Blake2b, Poly1305, SHA2-256, SHA3-256 and
		512, MD5. Other: CRC32 and Adler32 checksums, Hex, Base64 and 
		Base58 encoding)
    ]],
    homepage = "http://github.com/philanc/plc",
    license = "MIT/X11",
}

dependencies = { "lua >= 5.3" }

build = {
    type = "builtin",
    modules = {
        ["plc.aead_chacha_poly"] = "plc/aead_chacha_poly.lua",
        ["plc.base58"] = "plc/base58.lua",
        ["plc.base58"] = "plc/base58.lua",
        ["plc.bin"] = "plc/bin.lua",
        ["plc.blake2b"] = "plc/blake2b.lua",
        ["plc.box"] = "plc/box.lua",
        ["plc.chacha20"] = "plc/chacha20.lua",
        ["plc.checksum"] = "plc/checksum.lua",
        ["plc.ec25519"] = "plc/ec25519.lua",
        ["plc.md5"] = "plc/md5.lua",
        ["plc.norx"] = "plc/norx.lua",
        ["plc.norx32"] = "plc/norx32.lua",
        ["plc.poly1305"] = "plc/poly1305.lua",
        ["plc.rabbit"] = "plc/rabbit.lua",
        ["plc.rc4"] = "plc/rc4.lua",
        ["plc.salsa20"] = "plc/salsa20.lua",
        ["plc.sha2"] = "plc/sha2.lua",
        ["plc.sha3"] = "plc/sha3.lua",
        ["plc.xtea"] = "plc/xtea.lua",
    },
    copy_directories = {},
}
