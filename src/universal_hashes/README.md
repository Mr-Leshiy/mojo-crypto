# Universal Hashes

Mojo implementations of [universal hash functions][1] — keyed hashes used as the
core of message authentication codes (MACs), typically inside AEAD constructions
such as AES-GCM and AES-GCM-SIV.

All algorithms share the `UniversalHashable` trait (`traits.mojo`): construct
from a `KEY_SIZE`-byte key, absorb `BLOCK_SIZE` blocks via `update` /
`update_padded`, then `finalize` into a `TAG_SIZE`-byte tag.

## Implemented algorithms

| Algorithm | Directory | Description |
|-----------|-----------|-------------|
| [GHASH](ghash/README.md)     | `ghash/`   | GF(2¹²⁸) hash used by AES-GCM |
| [POLYVAL](polyval/README.md) | `polyval/` | GF(2¹²⁸) hash used by AES-GCM-SIV (byte-reversed GHASH) |

## References

- [Wikipedia — Universal hashing][1]
- [RFC 8452 — AES-GCM-SIV][2] (Appendix A relates GHASH and POLYVAL)

[1]: https://en.wikipedia.org/wiki/Universal_hashing
[2]: https://www.rfc-editor.org/rfc/rfc8452
