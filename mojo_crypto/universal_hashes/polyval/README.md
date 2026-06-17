# POLYVAL

Mojo implementation of [POLYVAL][1], a universal hash function over GF(2¹²⁸)
defined modulo the polynomial `x¹²⁸ + x¹²⁷ + x¹²⁶ + x¹²¹ + 1`.

POLYVAL is the authentication component of [AES-GCM-SIV][1], specified in
[RFC 8452][1]. It is the little-endian "mirror" of [GHASH](../ghash/README.md)
(their polynomials are byte-reversed), making it faster on little-endian
architectures while remaining able to compute GHASH/GMAC. Block, key, and tag
sizes are all 16 bytes.

## References

- [RFC 8452 — AES-GCM-SIV][1] (§ 3 defines POLYVAL; Appendix A relates it to GHASH)
- [RustCrypto — `polyval`][2]

[1]: https://www.rfc-editor.org/rfc/rfc8452
[2]: https://github.com/RustCrypto/universal-hashes/tree/master/polyval
