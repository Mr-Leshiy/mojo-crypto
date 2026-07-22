# SHA-2

Mojo implementation of the [SHA-2][1] family as specified in [FIPS 180-4][2].

Only a naive, portable CPU implementation exists so far — no hardware
acceleration yet (e.g. ARMv8/x86 SHA extensions).

Two engines share the Merkle-Damgard structure but differ in word size,
block size, round count, and rotation amounts; the six named algorithms are
each just an initial hash value and an output truncation on top of one of
them:

| Algorithm | Engine | Block size | Output size |
|-----------|--------|------------|-------------|
| SHA-224 | `Sha2Cpu32` (32-bit words) | 64 bytes | 28 bytes |
| SHA-256 | `Sha2Cpu32` (32-bit words) | 64 bytes | 32 bytes |
| SHA-384 | `Sha2Cpu64` (64-bit words) | 128 bytes | 48 bytes |
| SHA-512 | `Sha2Cpu64` (64-bit words) | 128 bytes | 64 bytes |
| SHA-512/224 | `Sha2Cpu64` (64-bit words) | 128 bytes | 28 bytes |
| SHA-512/256 | `Sha2Cpu64` (64-bit words) | 128 bytes | 32 bytes |

## References

- [FIPS 180-4 — Secure Hash Standard (SHS)][2]
- [Wikipedia — SHA-2][1]
- [RustCrypto — `sha2`][3]

[1]: https://en.wikipedia.org/wiki/SHA-2
[2]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
[3]: https://github.com/RustCrypto/hashes/tree/master/sha2
