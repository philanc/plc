local box = require "plc.box"

local function new_key()
    -- Note: we use math.random in this test because it is portable,
    -- but to generate a real key you should use a better RNG, for
    -- instance /dev/urandom on Linux.
    local t = {}
    for i = 1, 32 do t[i] = math.random(0, 255) end
    return string.char(table.unpack(t))
end

local sk_a, sk_b = new_key(), new_key()
local pk_a, pk_b = box.public_key(sk_a), box.public_key(sk_b)

local k = ("k"):rep(32)
local n = ("123456"):rep(4)
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
