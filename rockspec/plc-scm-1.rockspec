package = "plc"
version = "scm-1"

source = {
    url = "git://github.com/philanc/plc.git",
}

description = {
    summary = "Pure Lua Crypto",
    detailed = [[
        A pure Lua cryptograhy library.
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
        ["plc.base64"] = "plc/base64.lua",
        ["plc.base85"] = "plc/base85.lua",
        ["plc.bin"] = "plc/bin.lua",
        ["plc.blake2b"] = "plc/blake2b.lua",
        ["plc.box"] = "plc/box.lua",
        ["plc.chacha20"] = "plc/chacha20.lua",
        ["plc.checksum"] = "plc/checksum.lua",
        ["plc.ec25519"] = "plc/ec25519.lua",
        ["plc.gimli"] = "plc/gimli.lua",
        ["plc.md5"] = "plc/md5.lua",
        ["plc.morus"] = "plc/morus.lua",
        ["plc.norx"] = "plc/norx.lua",
        ["plc.norx32"] = "plc/norx32.lua",
        ["plc.poly1305"] = "plc/poly1305.lua",
        ["plc.rabbit"] = "plc/rabbit.lua",
        ["plc.rc4"] = "plc/rc4.lua",
        ["plc.salsa20"] = "plc/salsa20.lua",
        ["plc.sha2"] = "plc/sha2.lua",
        ["plc.sha3"] = "plc/sha3.lua",
        ["plc.siphash"] = "plc/siphash.lua",
        ["plc.xtea"] = "plc/xtea.lua",
    },
    copy_directories = {},
}
