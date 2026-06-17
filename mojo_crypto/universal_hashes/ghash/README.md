# GHASH

Mojo implementation of [GHASH][1], a universal hash function over GF(2¹²⁸)
defined modulo the polynomial `x¹²⁸ + x⁷ + x² + x + 1`.

GHASH is the authentication component of [AES-GCM (Galois/Counter Mode)][1],
specified in [NIST SP 800-38D][2]. Block, key, and tag sizes are all 16 bytes.

## References

- [NIST SP 800-38D — Galois/Counter Mode (GCM) and GMAC][2]
- [Wikipedia — Galois/Counter Mode][1]
- [RustCrypto — `ghash`][3]

[1]: https://en.wikipedia.org/wiki/Galois/Counter_Mode
[2]: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
[3]: https://github.com/RustCrypto/universal-hashes/tree/master/ghash
