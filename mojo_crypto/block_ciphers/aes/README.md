# AES (Advanced Encryption Standard)

Mojo implementation of the [Advanced Encryption Standard (AES)][1] as specified in [FIPS 197][2].

Supports AES-128, AES-192, and AES-256 (16, 24, and 32-byte keys). Block size is 128 bits (16 bytes).

The `Aes[KeySize, Backend]` struct selects the implementation at compile time. Available backends:

- **ARMv8 AES crypto extension** (`AesArmv8Backend`, recommended) — via LLVM `aese`/`aesmc`/`aesd`/`aesimc` intrinsics
- **x86 AES-NI** (`AesX86Backend`, recommended) — via LLVM `aesenc`/`aesenclast`/`aesdec`/`aesdeclast` intrinsics
- **Portable software** (`AesCpuBackend`) — straightforward FIPS 197 reference implementation
- **CUDA GPU** (`AesGpuBackend`) — per-block thread kernel with shared-memory state

## References

- [FIPS 197 — Advanced Encryption Standard][2]
- [Wikipedia — Advanced Encryption Standard][1]

[1]: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
[2]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
