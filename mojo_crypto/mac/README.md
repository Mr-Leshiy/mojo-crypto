# Message Authentication Codes (MAC)

Mojo implementations of [message authentication codes][1] — keyed algorithms
that produce a fixed-size tag authenticating a message's integrity and origin.

## Implemented algorithms

| Algorithm | Directory | Specification | Description |
|-----------|-----------|---------------|-------------|
| CMAC (OMAC1) | `cmac/` | NIST SP 800-38B, RFC 4493 | Cipher-based MAC built from a block cipher (e.g. AES-CMAC) |


## References

- [Wikipedia — One-key MAC (CMAC / OMAC)][1]
- [RustCrypto — MACs][2]
- [NIST SP 800-38B — The CMAC Mode for Authentication][3]
- [RFC 4493 — The AES-CMAC Algorithm][4]

[1]: https://en.wikipedia.org/wiki/One-key_MAC
[2]: https://github.com/RustCrypto/MACs
[3]: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38b.pdf
[4]: https://www.rfc-editor.org/rfc/rfc4493
