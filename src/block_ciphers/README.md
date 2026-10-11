# Block Ciphers

Mojo implementations of [block ciphers][1] — keyed, deterministic permutations
that transform a fixed-size block of plaintext into a block of ciphertext.

## Implemented ciphers

| Cipher | Directory | Specification | Description |
|--------|-----------|---------------|-------------|
| [AES](aes/README.md) | `aes/` | FIPS 197 | Advanced Encryption Standard (AES-128/192/256), with naive, ARMv8, x86 AES-NI, and GPU backends |

## Modes of operation

Block ciphers process a single block; [modes of operation](modes/README.md)
(`modes/`) extend them to messages of arbitrary length.

## References

- [Wikipedia — Block cipher][1]
- [RustCrypto — block-ciphers][2]

[1]: https://en.wikipedia.org/wiki/Block_cipher
[2]: https://github.com/RustCrypto/block-ciphers
