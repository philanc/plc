std = "lua53"

ignore = {
    -- allow setting _ENV
    "211/_ENV",
    -- allow unused arguments ending with _
    "212/.*_",
    -- allow never accessed variables ending with _
    "231/.*_",
    -- empty if branch
    "542",
}

files["test/test_sha3.lua"] = {
    ignore = {
        -- line too long
        "631",
    }
}

exclude_files = {
    -- work in progress
    "plc/xtea.lua",
    "test/test_xtea.lua",
    -- functions commented out
    "test_perf.lua",
}
