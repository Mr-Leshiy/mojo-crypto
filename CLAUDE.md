# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

All commands use [pixi](https://pixi.sh) for environment management:

```bash
pixi run fmt          # format all Mojo source files
pixi run test         # run the AES test suite (requires GPU)
pixi run bench        # run Mojo AES benchmarks at -O3 (requires GPU)
pixi run bench-rust   # run Rust AES benchmarks (via Criterion)
```

Tests and benchmarks require an NVIDIA CUDA GPU. CI only runs `fmt` because free GitHub-hosted runners have no GPU.

To run tests directly (equivalent to `pixi run test`):
```bash
mojo run -I . tests/block_ciphers/aes/test_aes.mojo
```

## Architecture

### Trait layer (`mojo_crypto/block_cipher.mojo`)

Two traits define the public interface:
- `BlockCipher` — CPU encrypt/decrypt, takes `InlineArray[UInt8, Size]` by `mut` reference
- `GpuBlockCipher` — GPU encrypt/decrypt, same but also takes a `DeviceContext`

`Size` must be a compile-time multiple of 16 (enforced by `_assert_block_aligned`, a `comptime assert`).

### `Aes[KeySize]` struct (`mojo_crypto/block_ciphers/aes/aes.mojo`)

The main struct implements both traits. `KeySize` is 16 (AES-128), 24 (AES-192), or 32 (AES-256) — validated at comptime. Round count `Nr = KeySize/4 + 6`.

GPU support is opt-in: pass a `DeviceContext` to `__init__` and it populates `_gpu: Optional[AesGpuSetup]`. GPU methods raise `GpuContextError` if called without it. `AesGpuSetup` holds pre-allocated `DeviceBuffer`s for the key schedule and S-boxes — these are uploaded once at construction and reused across all calls.

Multi-block CPU path: `_encrypt_cpu`/`_decrypt_cpu` use a `comptime for` loop over `Size // BLOCK_SIZE` blocks, so the iteration count is unrolled at compile time.

Multi-block GPU path: `grid_dim = num_blocks`, `block_dim = BLOCK_SIZE (16)`. Each GPU thread block processes exactly one AES block, with 16 threads (one per byte) operating on a shared-memory state array.

### CPU cipher (`mojo_crypto/block_ciphers/aes/cpu/cipher.mojo`)

Straightforward FIPS 197 implementation. State layout is column-major: `state[r][c] ↔ state[r + 4*c]`. GF(2⁸) multiplication uses Russian-peasant via `multiply`/`xtime`.

### ARMv8 hardware cipher (`mojo_crypto/block_ciphers/aes/aarch64/`)

Uses ARMv8 Crypto Extension via LLVM intrinsics (`llvm.aarch64.crypto.aese/aesmc/aesd/aesimc`). All four operate on `SIMD[DType.uint8, 16]` directly.

`AESE` fuses `AddRoundKey` (XOR) *before* `SubBytes+ShiftRows`, producing a lag-by-one key schedule: `cipher()` runs `aesmc(aese(s, rks[r]))` for rounds `0..Nr-2`, then `aese(s, rks[Nr-1])` followed by `s ^= rks[Nr]`. `decipher()` uses `aesd`/`aesimc` with the equivalent-inverse key schedule from `setup.mojo`.

`setup.mojo` exports `AesArmv8Setup[KeySize]`, which precomputes both `enc_rks` and `dec_rks` at construction. The decryption schedule is built by `_dec_from_enc_rks`: `dk[0]=ek[Nr]`, inner keys `dk[1..Nr-1]=aesimc(ek[Nr-r])`, `dk[Nr]=ek[0]`.

Dispatched from `aes.mojo` when `CompilationTarget.has_neon()` is true at comptime (NEON is mandatory on AArch64 and implies the AES crypto extension).

### x86 AES-NI cipher (`mojo_crypto/block_ciphers/aes/x86/`)

Uses x86 AES-NI via LLVM intrinsics (`llvm.x86.aesni.aesenc/aesenclast/aesdec/aesdeclast/aesimc`). These intrinsics are typed as `v2i64` in LLVM IR; `cipher.mojo` bitcasts to/from `SIMD[DType.uint64, 2]` internally via `_to_v2i64`/`_from_v2i64` helpers, keeping the public API consistent with the AArch64 backend (`SIMD[DType.uint8, 16]`).

`AESENC` folds `AddRoundKey` at the *end* (after MixColumns), so the key schedule is standard FIPS 197 order: `cipher()` does an explicit `s ^= rks[0]`, then `aesenc(s, rks[r])` for rounds `1..Nr-1`, then `aesenclast(s, rks[Nr])`. `decipher()` mirrors this with `aesdec`/`aesdeclast` and the same equivalent-inverse schedule as the AArch64 backend.

`setup.mojo` exports `AesX86Setup[KeySize]` with the same `enc_rks`/`dec_rks` structure as `AesArmv8Setup`. **Not yet wired into `aes.mojo` dispatch** — see `PLAN.md` Phase 2/3.

### GPU cipher (`mojo_crypto/block_ciphers/aes/gpu/cipher.mojo`)

Each thread handles one byte (`thread_idx.x` = local byte index, `block_idx.x` = AES block index). State lives in `AddressSpace.SHARED`. `shift_rows` and `mix_columns` require `barrier()` calls to prevent read-after-write races between threads in the same block.

### Key expansion (`mojo_crypto/block_ciphers/aes/expand.mojo`)

FIPS 197 Algorithm 2. Parameterised by `[WordsSize, Nk, KeySize]`. `Nk = KeySize/4`, `WordsSize = Nb*(Nr+1)`.

### Test vectors (`tests/block_ciphers/aes/`)

NIST KAT and MCT `.rsp` files are loaded via a Python helper (`tests/block_ciphers/aes/load_test_vectors.py`). `utils.mojo` bridges Mojo and Python via `std.python`. Tests cover both CPU and GPU paths with the same vectors.

### Known GPU performance issues

`docs/gpu-performance-review.md` documents outstanding GPU bottlenecks in priority order: warp divergence in `multiply`, global-memory S-box/key-schedule accesses, and only 16 threads per block (half a warp). Consult that document before working on GPU optimisations.
