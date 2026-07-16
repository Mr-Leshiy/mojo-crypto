# mojo-crypto

Cryptographic primitives implemented in [Mojo](https://www.modular.com/mojo),
with portable software backends alongside hardware-accelerated (ARMv8 Crypto
Extension, x86 AES-NI/PCLMULQDQ) and GPU implementations.

## Documentation

Full API documentation is published at
**<https://Mr-Leshiy.github.io/mojo-crypto/>**, generated from the source with
[Modo](https://mlange-42.github.io/modo/). Build it locally with `pixi run docs`.

## Modules

- **[`aead`](mojo_crypto/aead/)** — Authenticated Encryption with Associated
  Data: AES-GCM and AES-GCM-SIV.
- **[`block_ciphers`](mojo_crypto/block_ciphers/)** — block ciphers (AES, with
  CPU / ARMv8 / x86 / GPU backends) and modes of operation (CTR).
- **[`universal_hashes`](mojo_crypto/universal_hashes/)** — GHASH and POLYVAL
  universal hash functions.
- **[`macs`](mojo_crypto/macs/)** — message authentication codes: CMAC
  (OMAC1).
- **[`containers`](mojo_crypto/containers/)** — supporting containers and
  encodings (hex).

## Requirements

- [pixi](https://pixi.sh) — manages the Mojo toolchain and dependencies

## Commands

```bash
pixi run fmt         # format all Mojo sources
pixi run test        # run the test suite (requires a GPU)
pixi run bench       # run the Mojo benchmarks (requires a GPU)
pixi run bench-rust  # run the Rust reference benchmarks
pixi run docs        # build the API documentation site
```

