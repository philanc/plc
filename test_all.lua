require "test.test_bin"
require "test.test_base64"
require "test.test_base58"

-- checksums, crypto hashes
require "test.test_checksum"
require "test.test_md5"
require "test.test_sha2"
require "test.test_sha3"
require "test.test_blake2b"

--encryption
require "test.test_rc4"
require "test.test_xtea"
require "test.test_rabbit"
require "test.test_salsa20"
require "test.test_chacha20"
require "test.test_poly1305"
require "test.test_aead_chacha_poly"
require "test.test_norx"
require "test.test_norx32"

-- pk / EC scalar mult for DH key exchange
require "test.test_ec25519"

-- NaCl box(), secret_box()
require "test.test_box"

