-- Copyright (c) 2018  Phil Leblanc  -- see LICENSE file
------------------------------------------------------------------------

--[[ 

=== plc - crude performance tests


]]

local bin = require "plc.bin"
local stx = bin.stohex
local xts = bin.hextos
local function px(s) print(stx(s, 16, " ")) end
local function pf(...) print(string.format(...)) end

local function pst(st)
	for i = 1,8 do
		pf("x[%d]:  %08X     c[%d]:  %08X",
			i, st.x[i], i, st.c[i] )
	end
end

local spack, sunpack = string.pack, string.unpack
local app, concat = table.insert, table.concat
local char, byte, strf = string.char, string.byte, string.format

------------------------------------------------------------------------
local rc4 = require "plc.rc4"
local rabbit = require "plc.rabbit"
local cha = require "plc.chacha20"
local salsa = require "plc.salsa20"
local sha2 = require "plc.sha2"
local sha3 = require "plc.sha3"
local poly = require "plc.poly1305"
local chk = require "plc.checksum"
local xtea = require "plc.xtea"
local blake2b = require "plc.blake2b"
local norx = require "plc.norx"
local norx32 = require "plc.norx32"
local md5 = require "plc.md5"
local morus = require "plc.morus"
local ec25519 = require "plc.ec25519"

local base64 = require "plc.base64"
local base58 = require "plc.base58"
local base85 = require "plc.base85"

------------------------------------------------------------

local t0, c0, t1, c1, desc, cmt, sizemb

local function start(d, c)
	desc = d
	cmt = c and "-- " .. c or "" --optional comment
	t0, c0 = os.time(), os.clock()
end

local function done()
	local dt = os.time()-t0
	local dc = os.clock()-c0
	pf("- %-20s %7.1f  %s", desc, dc, cmt)
end

local sizemb = 10  -- plain text size (in MBytes)
local mega = 1024 * 1024
local size = mega * sizemb
local plain = ('a'):rep(size)
local k32 = ('k'):rep(32)
local k16 = ('k'):rep(16)
local iv8 = ('i'):rep(8)

------------------------------------------------------------

local function perf_md5()
	local m = plain

	for j = 1, 1 do
		start("md5")
		local dig = md5.hash(m)
		done()
	end
	--
end	--perf_md5

------------------------------------------------------------

local function perf_sha2()
	local et, h  -- encrypted text, hash/hmac

	start("sha2-256")
	h = sha2.sha256(plain)
	done()

	start("sha2-512")
	h = sha2.sha512(plain)
	done()

end --perf_sha2

------------------------------------------------------------

local function perf_sha3()
	local et, h  -- encrypted text, hash/hmac

	start("sha3-256")
	h = sha3.sha256(plain)
	done()

	start("sha3-512")
	h = sha3.sha512(plain)
	done()
end --perf_sha3


------------------------------------------------------------

local function perf_blake2b()
	local dig
	--
	for j = 1, 1 do
		start("blake2b-512")
		dig = blake2b.hash(plain)
		done()
	end
	--
	for j = 1, 1 do
		start("blake2b-256")
		dig = blake2b.hash(plain, 32) -- 32-byte digest
		done()
	end
	--
end	--perf_blake2b




------------------------------------------------------------

local function perf_encrypt()
	local nonce = ('n'):rep(12)
	local nonce8 = ('n'):rep(8)
	local counter = 1
	local aad = "\x50\x51\x52\x53\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7"
	local iv = "\x40\x41\x42\x43\x44\x45\x46\x47"
	local const = "\x07\x00\x00\x00"
	local et, h  -- encrypted text, hash/hmac

	start("rc4 raw")
	et = rc4.rc4raw(k16, plain)
	done()

	start("rabbit")
	et = rabbit.encrypt(k16, iv8, plain)
	done()
		--
end --perf_encrypt

------------------------------------------------------------

local function perf_xtea()
	local sub = string.sub
	local et
	--
	start("xtea ctr")
	et = xtea.encrypt(k16, iv8, plain)
	done()
	--
	start("xtea", "encrypt block only")
	local st = xtea.keysetup(k16)
	for i = 1, #plain//8 do
		xtea.encrypt_u64(st, 0xaaaa5555aaaa5555)
	end
	done()
	--
end	--perf_xtea

------------------------------------------------------------

local function perf_encrypt20()
	local nonce = ('n'):rep(12)
	local nonce8 = ('n'):rep(8)
	local counter = 1
	local aad = "\x50\x51\x52\x53\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7"
	local iv = "\x40\x41\x42\x43\x44\x45\x46\x47"
	local const = "\x07\x00\x00\x00"
	local et, h  -- encrypted text, hash/hmac

	start("chacha20")
	et = cha.encrypt(k32, counter, nonce, plain)
	done()

	start("salsa20")
	et = salsa.encrypt(k32, counter, nonce8, plain)
	done()
	--
end --perf_encrypt20

------------------------------------------------------------

local function perf_norx()
	local k = ('k'):rep(32)  -- key
	local n = ('n'):rep(32)  -- nonce
	local a = ('a'):rep(16)  -- header ad  (61 61 ...)
	local z = ('z'):rep(8)   -- trailer ad  (7a 7a ...)
	local m = plain
	--
	for i = 1, 1 do
		start("norx encrypt")
		local c = norx.aead_encrypt(k, n, plain, a, z)
		done()
		start("norx decrypt")
		local p = norx.aead_decrypt(k, n, c, a, z)
		assert(p == plain)
		done()
	end
	--
	for j = 1, 1 do
		local pt = {}
		local cnt = 256 * 10  -- cnt * 4k = 10mb
		for i = 1, cnt do pt[i] = (char(i%256)):rep(4096) end
		local ct = {}
		start("norx encrypt", "10mb, 4k messages")
		for i = 1, cnt do
			ct[i] = norx.aead_encrypt(k, n, pt[i])
		end
		done()
		start("norx decrypt", "10mb, 4k messages")
		for i = 1, cnt do
			local p = norx.aead_decrypt(k, n, ct[i])
		end
		done()
	end
	--
end	--perf_norx

------------------------------------------------------------

local function perf_norx32()
	local k = ('k'):rep(16)  -- key
	local n = ('n'):rep(16)  -- nonce
	local a = ('a'):rep(16)  -- header ad  (61 61 ...)
	local z = ('z'):rep(8)   -- trailer ad  (7a 7a ...)
	local m = plain

	for j = 1, 1 do
		start("norx32 encrypt")
		local c = norx32.aead_encrypt(k, n, plain, a, z)
		done()
		start("norx32 decrypt")
		local p = norx32.aead_decrypt(k, n, c, a, z)
		assert(p == plain)
		done()
	end
	--
end	--perf_norx32

------------------------------------------------------------

local function perf_morus()
	local k = ('k'):rep(16)  -- key
	local n = ('n'):rep(16)  -- nonce
	local a = ('a'):rep(16)  -- ad  (61 61 ...)
	local sizemb = 100 
	local m = ('m'):rep(sizemb * 1024 * 1024)

	for j = 1, 1 do
		start("morus encrypt", "100mb")
		local c = morus.encrypt(k, n, m)
		done()
		start("morus decrypt", "100mb")
		local p = morus.decrypt(k, n, c)
		assert(p == m)
		done()
		start("morus-based xof", "100mb")
		local c = morus.x_hash(m)
		done()

	end
	--
end	--perf_morus

------------------------------------------------------------

local function perf_ec25519()
	local base = ec25519.base
	--
	start("ec25519 scalarmult", "100 times")
	for i = 1, 100 do et = ec25519.scalarmult(k32, base) end
	done()
	--
end --perf_ec25519

------------------------------------------------------------

local function perf_xor()
	--
	start("xor1, k16")
	et = bin.xor1(k16, plain)
	done()
	--
	-- xor64 removed
	--
	start("xor8, k16")
	et = bin.xor8(k16, plain)
	done()
	--
end --perf_xor

------------------------------------------------------------

local function perf_base()
	local et -- expected text
	local s64 = ("a"):rep(64) -- for base58 test

	start("base64 encode", "result: 13.3mb")
	et = base64.encode(plain)
	done()

	start("base64 decode", "result: 7.5mb")
	et = base64.decode(plain)
	done()

	start("base85 encode", "result: 12.5mb")
	et = base85.encode(plain)
	done()

	start("base85 decode", "result: 8mb")
	et = base85.decode(plain)
	done()

	start("base58 encode", "64 bytes x 10,000")
	for i = 1, 10000 do et = base58.encode(s64) end
	done()

	start("base58 decode", "64 bytes x 10,000")
	for i = 1, 10000 do et = base58.decode(s64) end
	done()


end --perf_base

------------------------------------------------------------

local function perf_misc()
	local et, h  -- encrypted text, hash/hmac

	start("adler-32")
	h = chk.adler32(plain)
	done()

	start("crc-32")
	h = chk.crc32(plain)
	done()

	start("crc-32 (no table)")
	h = chk.crc32_nt(plain)
	done()

	start("poly1305 hmac")
	h = poly.auth(plain, k32)
	done()

end --perf_misc



------------------------------------------------------------

print(_VERSION)

print("Plain text: 10 MBytes except where noted")
print("Elapsed times in seconds")

print("\n-- hash \n")

perf_md5()
perf_sha2()
perf_sha3()
perf_blake2b()

print("\n-- encryption \n")

perf_encrypt()
perf_xtea()
perf_encrypt20()
perf_norx()
perf_norx32()
perf_morus()

print("\n-- elliptic curve \n")

perf_ec25519()

print("\n-- base<n> encoding \n")

perf_base()

print("\n-- misc \n")

perf_misc()
perf_xor()

--[[

tests run on an average/old laptop
(Linux 4.4 x86_64CPU Intel i5 M430 @2.27GHz)
with Lua 5.3.4 

Plain text: 10 MBytes except where noted
Elapsed times in seconds

-- hash

- md5                      3.7  
- sha2-256                 9.1  
- sha2-512                 6.4  
- sha3-256                23.2  
- sha3-512                43.0  
- blake2b-512              9.4  
- blake2b-256              9.3  

-- encryption

- rc4 raw                  7.4  
- rabbit                   4.7  
- xtea ctr                11.0  
- xtea                     8.9  -- encrypt block only
- chacha20                 7.9  
- salsa20                  8.0  
- norx encrypt             4.5  
- norx decrypt             3.7  
- norx encrypt             3.9  -- 10mb, 4k messages
- norx decrypt             4.3  -- 10mb, 4k messages
- norx32 encrypt           9.2  
- norx32 decrypt           7.9  
- morus encrypt           16.8  -- 100mb
- morus decrypt           14.8  -- 100mb
- morus-based xof         10.1  -- 100mb

-- elliptic curve

- ec25519 scalarmult      18.9  -- 100 times

-- base<n>

- base64 encode            7.1  -- result: 13.3mb
- base64 decode            5.5  -- result: 7.5mb
- base85 encode            4.0  -- result: 12.5mb
- base85 decode            3.8  -- result: 8mb
- base58 encode           13.7  -- 64 bytes x 10,000
- base58 decode            2.4  -- 64 bytes x 10,000

-- misc

- adler-32                 1.3  
- crc-32                   1.8  
- crc-32 (no table)        5.9  
- poly1305 hmac            1.2  
- xor1, k16                7.8  
- xor8, k16                1.2  


]]
