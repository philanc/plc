-- Copyright (c) 2023  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------

--[[

=== test_ascon  (ascon128)

Ascon128 - AEAD Encryption, HASH, MAC, PRF

(test results computed with the Ascon C reference implementation)

]]

local bin = require "plc.bin"
local stx, xts = bin.stohex, bin.hextos

local ascon = require "plc.ascon"

local encrypt = ascon.aead_encrypt
local decrypt = ascon.aead_decrypt
local hash = ascon.hash
local mac = ascon.mac
local prf = ascon.prf


local function test_encrypt()
	local h, k, n, m, e, m2, err, ad
	-- AEAD encryption
	-- 16-byte key, 16-byte nonce, 16-byte auth tag
	k = "abcdefghijklmnop"
	n = "nnnnnnnnnnnnnnnn"
	m = ""; ad = nil -- default to empty string
	e = encrypt(k, n, m, ad)
	assert(e == xts[[bccf97f50336090c0c7215716c9d4766]])
	m2 = decrypt(k,n,e,ad); assert(m2 == m)
	m = ""; ad = "A"
	e = encrypt(k, n, m, ad)
	assert(e == xts[[289848b6adb7b0ba1850cd6d586914b4]])
	m2 = decrypt(k,n,e,ad); assert(m2 == m)
	m = "a"; ad = ""
	e = encrypt(k, n, m, ad)
	assert(e == xts[[2067a522ad5c4409cf78e9c684da3435e2]])
	m2 = decrypt(k,n,e,ad); assert(m2 == m)
	m = "abcdefghi"; ad = "" 
	e = encrypt(k, n, m, ad)
	assert(e == xts[[
		20945fc794adf584aa64ca1c510802bb123ba77715ad24ef60]])
	m2 = decrypt(k,n,e,ad); assert(m2 == m)
	m = "abcdefgh"; ad = "12345678" -- just one block(m,ad)
	e = encrypt(k, n, m, ad)
	assert(e == xts[[
		32ed6d7145bf3c4454a4367ed9e5952990fac87173e0ad1d]])
	m2 = decrypt(k,n,e,ad); assert(m2 == m)
	m = "abcdefghij"; ad = "1234567890" -- more than one block (m,ad)
	e = encrypt(k, n, m, ad)
	assert(e == xts[[
		4e31ada9034dea60ea2263495305a9fdee6093dee3836ea24a2c]])
	m2 = decrypt(k,n,e,ad); assert(m2 == m)
	
end--test_encrypt()

local function test_hash()
	h = hash("ascon")
	assert(h == xts[[
		02c895cb92d79f195ed9e3e2af89ae30
		7059104aaa819b9a987a76cf7cf51e6e
	]])
	h = mac("abcdefghijklmnop", "ascon")
	assert(h == xts"5829fd289ae4b3ccba504f803ef3cee3")
	h = prf("abcdefghijklmnop", "ascon")
	assert(h == xts"7d7453dc0272ef2100de117484ccfa7a")
	h = prf("abcdefghijklmnop", "ascon", 23)
	assert(h == xts"7d7453dc0272ef2100de117484ccfa7abd101a261e8bf7")

end--test_hash()

test_encrypt()
test_hash()

print("test_ascon: ok")
