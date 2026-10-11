# SHA-3

Mojo implementation of the [SHA-3][1] family and the SHAKE
extendable-output functions (XOFs), as specified in [FIPS 202][2].

Only a naive, portable implementation exists so far — no hardware
acceleration yet (e.g. ARMv8 SHA3 Crypto Extension).

Unlike SHA-2, SHA-3 is not a Merkle-Damgard construction: it is built on
the Keccak-*f*[1600] permutation used as a sponge (FIPS 202 §4). All six
algorithms share the same absorb/permute/squeeze machinery and differ only
in their rate (the sponge's block size) and domain-separation suffix; the
fixed-digest algorithms additionally fix an output length, while SHAKE
exposes `squeeze` for output of any length.

| Algorithm | Rate (block size) | Output size |
|-----------|--------------------|-------------|
| SHA3-224  | 144 bytes          | 28 bytes |
| SHA3-256  | 136 bytes          | 32 bytes |
| SHA3-384  | 104 bytes          | 48 bytes |
| SHA3-512  | 72 bytes           | 64 bytes |
| SHAKE128  | 168 bytes          | extendable |
| SHAKE256  | 136 bytes          | extendable |

## References

- [FIPS 202 — SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions][2]
- [Keccak reference][3]
- [Wikipedia — SHA-3][1]
- [RustCrypto — `sha3`][4]

[1]: https://en.wikipedia.org/wiki/SHA-3
[2]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
[3]: https://keccak.team/keccak.html
[4]: https://github.com/RustCrypto/hashes/tree/master/sha3
