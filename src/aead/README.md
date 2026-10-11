# Authenticated Encryption with Associated Data (AEAD)

Mojo implementations of [AEAD][1] schemes — constructions that simultaneously
provide **confidentiality** for the message and **integrity/authenticity** for
both the message and any associated data (`aad`) that travels alongside it.

## Implemented schemes

| Scheme | File | Specification |
|--------|------|---------------|
| GCM (Galois/Counter Mode) | `gcm.mojo` | NIST SP 800-38D |
| GCM-SIV (nonce-misuse-resistant) | `gcm_siv.mojo` | RFC 8452 |

## References

- [Wikipedia — Authenticated encryption][1]
- [NIST SP 800-38D — Galois/Counter Mode (GCM) and GMAC][2]
- [RFC 8452 — AES-GCM-SIV: Nonce Misuse-Resistant AEAD][3]

[1]: https://en.wikipedia.org/wiki/Authenticated_encryption
[2]: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
[3]: https://www.rfc-editor.org/rfc/rfc8452
