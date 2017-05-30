-- Copyright (c) 2015  Phil Leblanc  -- see LICENSE file
------------------------------------------------------------------------
-- crude performance tests


local bin = require"bin"
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
local strf = string.format

------------------------------------------------------------------------
local rc4 = require "rc4"
local rabbit = require "rabbit"
local cha = require "chacha20"
local sha2 = require "sha2"
local sha3 = require "sha3"
local poly = require "poly1305"
local chk = require "checksum"
local xtea = require "xtea"
local blake2b = require "blake2b"


local base64 = require "base64"
local base58 = require "base58"

------------------------------------------------------------

local t0, c0, t1, c1, desc, cmt, sizemb

local function start(d, c)
	desc = d
	cmt = c or "" --optional comment
	t0, c0 = os.time(), os.clock()
end
	
local function done()
	local dt, dc = os.time()-t0, os.clock()-c0
	pf("- %-20s %6d %9.2f   %s", desc, dt, dc, cmt)
end

local sizemb = 10  -- plain text size (in MBytes)
local mega = 1024 * 1024
local size = mega * sizemb
local plain = ('a'):rep(size)
local k32 = ('k'):rep(32)
local k16 = ('k'):rep(16)
local iv8 = ('i'):rep(8)

------------------------------------------------------------

local function perf_encrypt()
	local nonce = ('n'):rep(12)
	local counter = 1
	local aad = "\x50\x51\x52\x53\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7"
	local iv = "\x40\x41\x42\x43\x44\x45\x46\x47"
	local const = "\x07\x00\x00\x00"
	local et, h  -- encrypted text, hash/hmac
	
	print("Plain text size (in MBytes):", sizemb)
	print("Times:  elapsed (wall) and CPU (clock) in seconds")

	start("rabbit")
	et = rabbit.encrypt(k16, iv8, plain)
	done()

	start("rc4 raw")
	et = rc4.rc4raw(k16, plain)
	done()

	start("rabbit")
	et = rabbit.encrypt(k16, iv8, plain)
	done()
	
	start("chacha20")
	et = cha.encrypt(k32, counter, nonce, plain)	
	done()
	--
end --perf_encrypt

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

local function perf_sha2_sha3()
	local et, h  -- encrypted text, hash/hmac
	
	print("Plain text size (in MBytes):", sizemb)
	print("Times:  elapsed (wall) and CPU (clock) in seconds")

	start("sha2-256")
	h = sha2.hash256(plain)
	done()

	start("sha3-256")
	h = sha3.hash256(plain)
	done()

	start("sha3-512")
	h = sha3.hash512(plain)
	done()
end --perf_sha2_sha3

------------------------------------------------------------

local function perf_misc()
	local et, h  -- encrypted text, hash/hmac
	
	print("Plain text size (in MBytes):", sizemb)
	print("Times:  elapsed (wall) and CPU (clock) in seconds")

	start("base64 encode", "(res: 13.3MB)")
	et = base64.encode(plain)
	done()

	start("base64 decode", "(res: 7.5MB)")
	et = base64.decode(plain)
	done()

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

local function perf_xtea()
	local sub = string.sub
	local et
	--
	start("xtea ctr")
	et = xtea.encrypt(k16, iv8, plain)
	done()
	--
	start("xtea (encr block only)")
	local st = xtea.keysetup(k16)
	for i = 1, #plain//8 do 
		xtea.encrypt_u64(st, 0xaaaa5555aaaa5555) 
	end
	done()
	--
end	--perf_xtea

------------------------------------------------------------

local function perf_blake2b()
	local dig
	--
	
	print("Text size (in MBytes):", sizemb)
	print("Times:  elapsed (wall) and CPU (clock) in seconds")
	
	start("blake2b-512")
	dig = blake2b.hash(plain)
	done()
	--
	start("blake2b-256")
	dig = blake2b.hash(plain, 32) -- 32-byte digest
	done()
	--
end	--perf_blake2b



------------------------------------------------------------
--~ perf_encrypt()
--~ perf_xor()
--~ perf_sha2_sha3()
--~ perf_misc()
--~ perf_xtea()
perf_blake2b()

--[[

(tests run on a laptop - Linux 3.10, CPU i5 M430 @ 2.27 GHz)

Plain text size (in MBytes):	10
Times:  elapsed (os.time) and CPU (os.clock) in seconds

20151010 
- xtea ctr                 18     18.20   
- xtea (encr block only)   15     15.45   

20151009 
- rabbit                   10      9.53
- rc4 raw                  16     15.80
- chacha20                 17     16.94
- xor1, k16                11     11.25   
- xor64, k16                9      9.05   (removed)
- xor8, k16                 2      1.89   

- blake2b-512              13     13.28   
- blake2b-256              13     13.29   
- sha2-256                 30     30.22
- sha3-256                 54     54.53
- sha3-512                103    102.10

- base64 encode            13     12.60   (res: 13.3MB)
- base64 decode             8      8.67   (res: 7.5MB)
- adler-32                  3      2.62   
- crc-32                    4      3.68   
- crc-32 (no table)        12     11.30   
- poly1305 hmac             2      1.89   

]]