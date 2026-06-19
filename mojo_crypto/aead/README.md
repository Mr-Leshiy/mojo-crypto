# Authenticated Encryption with Associated Data (AEAD)

Mojo implementations of [AEAD][1] schemes — constructions that simultaneously
provide **confidentiality** for the message and **integrity/authenticity** for
both the message and any associated data (`aad`) that travels alongside it (for
example packet headers that must stay in the clear but must not be tampered
with).

## Implemented schemes

| Scheme | File | Specification |
|--------|------|---------------|
| GCM (Galois/Counter Mode) | `gcm.mojo` | NIST SP 800-38D |

## References

- [Wikipedia — Authenticated encryption][1]
- [NIST SP 800-38D — Galois/Counter Mode (GCM) and GMAC][2]

[1]: https://en.wikipedia.org/wiki/Authenticated_encryption
[2]: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
