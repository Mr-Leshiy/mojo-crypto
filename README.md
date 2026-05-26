# mojo-crypto

Cryptographic primitives implemented in [Mojo](https://www.modular.com/mojo).

## Requirements

- [pixi](https://pixi.sh) — manages the Mojo toolchain and dependencies

## Commands

```bash
pixi run fmt          # format all Mojo source files
pixi run test         # run the AES test suite
pixi run bench        # run Mojo AES benchmarks (-O3)
pixi run bench-rust   # run Rust AES benchmarks (Criterion)
```

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT license](LICENSE-MIT)

at your option.
