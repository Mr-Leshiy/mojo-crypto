# Message Authentication Codes (MAC)

Mojo implementations of [message authentication codes][1] — keyed algorithms
that produce a fixed-size tag authenticating a message's integrity and origin.

## Implemented algorithms

| Algorithm | Directory | Specification | Description |
|-----------|-----------|---------------|-------------|
| CMAC (OMAC1) | `cmac/` | NIST SP 800-38B, RFC 4493 | Cipher-based MAC built from a block cipher (e.g. AES-CMAC) |
| HMAC | `hmac/` | FIPS 198-1, RFC 2104 | Hash-based MAC built from a cryptographic hash function (e.g. HMAC-SHA-256) |


## References

- [Wikipedia — One-key MAC (CMAC / OMAC)][1]
- [RustCrypto — MACs][2]
- [NIST SP 800-38B — The CMAC Mode for Authentication][3]
- [RFC 4493 — The AES-CMAC Algorithm][4]
- [FIPS 198-1 — The Keyed-Hash Message Authentication Code (HMAC)][5]
- [RFC 2104 § 3 — Keys][6]

[1]: https://en.wikipedia.org/wiki/One-key_MAC
[2]: https://github.com/RustCrypto/MACs
[3]: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38b.pdf
[4]: https://www.rfc-editor.org/rfc/rfc4493
[5]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf
[6]: https://datatracker.ietf.org/doc/html/rfc2104#section-3
