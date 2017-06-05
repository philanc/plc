## PLC - Pure Lua Crypto

A small collection of crpytographic functions, and related utilities, implemented  in pure Lua  (version 5.3 or above)

### Recent changes

May-2017

* Added *NORX*, a *very* fast authenticated encryption algorithm.

* Added *Blake2b*, a strong cryptographic hash

Oct-2015

* Added *Rabbit*, a fast stream encryption algorithm.

* Added *XTea*, a very simple block encryption algorithm.

* Added some crude performance tests (see file 'test_perf.lua')


### Objective

Collect in one place standalone implementation of well-known, and/or useful,  and/or interesting cryptographic algorithms.

Users should be able to pickup any file and just drop it in their project:

* All the files are written in pure Lua, version 5.3 and above (tested on 5.3.3). Lua 5.3 is required since bit operators and string pack/unpack are extensively used.

* The files should not require any third-party library or C extension beyond the standard Lua 5.3 library. 

* The files should not define any global. When required, they should just return a table with the algorithm's functions and constants.

Contributions, fixes, bug reports and suggestions are welcome.

What this collection is *not*:

* a complete, structured cryptographic library - no promise is made about consistent API structure and documentation. This is not a library - just a collection of hopefully useful snippets of crypto source code. 

* high performance, heavy-duty cryptographic implementations -- after all, this is *pure* Lua...  :-)

*  memory-efficient implementations (see above)

*  memory-safe algorithms  -- Lua immutable strings are used and garbage-collected as needed. No guarantee is made that information, and in particular key material, is properly erased when no longer needed or do not leak.


### Functions

Encryption

* NORX, a *very* fast authenticated encryption algorithm with associated data (AEAD). NORX is a 3rd-round candidate to [CAESAR](http://competitions.cr.yp.to/caesar.html). This Lua code implements the default NORX 64-4-1 variant (state is 16 64-bit words, four rounds, no parallel execution, key and nonce are 256 bits)

* NORX32, a variant of NORX intended for smaller architectures (32-bit and less). Key and nonce are 128 bits. (Note that this NORX32 Lua implementation is half as fast as the default 64-bit NORX. It is included here only for compatibility with other implementations - In Lua, use the default NORX implementation!)

* Rabbit, a fast stream cipher, selected in the eSTREAM portfolio along with Salsa20, and defined in RFC 4503 (128-bit key, 64-bit IV - see more information and links in rabbit.lua)

* Chacha20, Poly1305 and authenticated stream encryption, as defined in RFC 7539

* RC4 - for lightweight, low strength encryption. Can also be used as a simple pseudo-random number generator.

Public key

* Elliptic curve cryptography: ec25519 (only low-level functions for the moment -
just enough to implement ECDH key exchange)

Hash

* Blake2b - Blake was a final round candidate in the NIST SHA-3 selection process.  Blake2b is an improved version of Blake. See https://blake2.net/. It has been specified in [RFC 7693](https://tools.ietf.org/html/rfc7693)

* SHA2 cryptographic hash family (only sha256 for the moment)

* SHA3 cryptographic hash family (formerly known as Keccak - 256-bit and 512-bit versions)

* Non-cryptographic checksums (CRC-32, Adler-32), ...

Some (un)related utilities: 

* Base64, Base58  and Hex encoding/decoding


### In the future...  

Implementations that may come some day:

* Salsa20 stream encryption (should be close to the Chacha20 implementation), and HSalsa20, allowing a pure Lua implementation of NaCl  ECDH key exchange and high level API (box(), secretbox())

* XChacha20 (ie. Chacha20 with a 24-byte nonce)

* SHA2-512

* better documentation in each file :-)

### Performance

These crude numbers give an idea of the relative performance of the algorithms. 
They correspond to the encryption or the hash of a 10 MB string (10 * 1024 * 1024 bytes). 

They have been collected on a laptop with Linux x86_64,  CPU i5 M430 @ 2.27 GHz.
Lua version is 5.3.3 (ELF 64 bits) - see file 'test_perf.lua'. 

```
Plain text size: 10 MBytes. Elapsed time in seconds

Encryption

	- norx                      4
	- norx32                    8   

	- rabbit                    5
	- chacha20                  9
	- rc4                       8
	- xtea ctr                 11  
	- xor8                      1

Hash
	- blake2b-512               9
	
	- sha2-256                 17
	- sha3-256                 23
	- sha3-512                 43
	
	- poly1305 hmac             1

	- adler-32                  1 
	- crc-32                    2 

```




### Test vectors, tests, and disclaimer

Some simplistic tests are provided in the 'test_xxx' files. 

The implementations should pass the tests, but beyond that, there is no guarantee that these implementations conform to anything  :-)  -- Use at your own risk!


### License

Except for some third-party implementations distributed under their specific terms, all the files included here are distributed under the MIT License (see file LICENSE)

Copyright (c) 2017  Phil Leblanc 


