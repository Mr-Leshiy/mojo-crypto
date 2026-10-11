# Hashes

Mojo implementations of [cryptographic hash functions][1].


## Implemented algorithms

| Algorithm | Directory | Specification | Description |
|-----------|-----------|---------------|-------------|
| [SHA-2](sha2/README.md) | `sha2/` | FIPS 180-4 | Merkle-Damgard hash family: SHA-224/256 (32-bit words) and SHA-384/512/512-224/512-256 (64-bit words) |
| [SHA-3](sha3/README.md) | `sha3/` | FIPS 202 | Keccak-*f*[1600] sponge family: SHA3-224/256/384/512 and the SHAKE128/256 extendable-output functions |

## References

- [Wikipedia — Cryptographic hash function][1]
- [RustCrypto — hashes][2]

[1]: https://en.wikipedia.org/wiki/Cryptographic_hash_function
[2]: https://github.com/RustCrypto/hashes
