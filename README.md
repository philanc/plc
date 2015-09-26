## PLC - Pure Lua Crypto

A small collection of crpytographic functions, and related utilities, implemented  in pure Lua  (version 5.3 or above)

### Objective

Collect in one place standalone implementation of well-known, and/or useful,  and/or interesting cryptographic algorithms.

Users should be able to pickup any file and just drop it in their project:

* All the files are written in pure Lua, version 5.3 and above (tested on 5.3.1). Lua 5.3 is required since bit operators and string pack/unpack are extensively used.

* The files should not require any third-party library or C extension beyond the standard Lua 5.3 library. 

* The files should not define any global. When required, they should just return a table with the algorithm's functions and constants.

Contributions, fixes, bug reports and suggestions are welcome.

What this collection is *not*:

* a complete, structured cryptographic library - no promise is made about consistent API structure and documentation. This is not a library - just a collection of hopefully useful snippets of crypto source code. 

* high performance, heavy-duty cryptographic implementations -- after all, this is *pure* Lua...  :-)

*  memory-efficient implementations (see above)

*  memory-safe algorithms  -- Lua immutable strings are used and garbage-collected as needed. No guarantee is made that information, and in particular key material, is properly erased when no longer needed or do not leak.


### Functions

* RC4 - for lightweight, low strength encryption. Can also be used as a simple pseudo-random number generator.

* Chacha20, Poly1305 and authenticated stream encryption, as defined in RFC 7539

* Elliptic curve cryptography: ec25519 (only low-level functions for the moment - barely enough to implement ECDH key exchange)

* SHA2 cryptographic hash family (only sha256 for the moment)

* SHA3 cryptographic hash family (formerly known as Keccak - 256-bit and 512-bit versions)

* Non-cryptographic checksums (CRC-32, Adler-32), ...

Some (un)related utilities: 

* Base64, Base58  and Hex encoding/decoding


Implementations to come:

* Salsa20 stream encryption (should be close to the Chacha20 implementation)

* NaCl - Dan Bernstein et al' Salsa20-Poly1305 authenticated stream encryption plus public key encryption based on elliptic curve ec25519, including ECDH key exchange, with a high level API (box(), secretbox())

* SHA2-512

What may come someday:

* better documentation in each file :-)

* AES, MD5, SHA1, RIPEMD-160, maybe DES/3DES (for old stuff)

What is not in the cards (except if some nice implementation is graciously contributed!):

* Arbitrary length integer arithmetic

* RSA  (-- rather focusing on ec25519 for public key and key exchange)

* All the NIST suite B ECC algorithms



### Test vectors, tests, and disclaimer

Some simplistic tests are provided in the 'test' directory. 

The implementations should pass the tests, but beyond that, there is no guarantee that these implementations conform to anything  :-)  -- Use at your own risk!


### License

Except for some third-party implementations distributed under their specific terms, all the files included here are distributed under the MIT License (see file LICENSE)

Copyright (c) 2015  Phil Leblanc 


