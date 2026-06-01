# Block Cipher Modes of Operation

This package implements the NIST-standardised modes of operation for block ciphers,
as specified in:

> **NIST Special Publication 800-38A** — *Recommendation for Block Cipher Modes of
> Operation: Methods and Techniques*
> https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

## Implemented modes

| Mode | File | SP 800-38A section |
|------|------|--------------------|
| CBC (Cipher Block Chaining) | `cbc.mojo` | § 6.2 |
| CTR (Counter)               | `ctr.mojo` | § 6.5 |

