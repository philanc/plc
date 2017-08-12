local box = require "box"

local pk_a, sk_a = box.keypair()
local pk_b, sk_b = box.keypair()

local k = ("k"):rep(32)
local n = ("n"):rep(24)
local pt = "abc"

do
    local et = assert(box.secretbox(pt, n, k))
    local dt = assert(box.secretbox_open(et, n, k))
    assert(dt == pt)
end

do
    local et = assert(box.box(pt, n, pk_b, sk_a))
    local dt = assert(box.box_open(et, n, pk_a, sk_b))
    assert(dt == pt)
end

print("test_box: ok")
