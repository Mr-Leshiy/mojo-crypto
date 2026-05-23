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
mojo run -I . tests/aes/test_aes.mojo
```

## Architecture

### Trait layer (`mojo_crypto/block_cipher.mojo`)

Two traits define the public interface:
- `BlockCipher` — CPU encrypt/decrypt, takes `InlineArray[UInt8, Size]` by `mut` reference
- `GpuBlockCipher` — GPU encrypt/decrypt, same but also takes a `DeviceContext`

`Size` must be a compile-time multiple of 16 (enforced by `_assert_block_aligned`, a `comptime assert`).

### `Aes[KeySize]` struct (`mojo_crypto/aes/aes.mojo`)

The main struct implements both traits. `KeySize` is 16 (AES-128), 24 (AES-192), or 32 (AES-256) — validated at comptime. Round count `Nr = KeySize/4 + 6`.

GPU support is opt-in: pass a `DeviceContext` to `__init__` and it populates `_gpu: Optional[AesGpuSetup]`. GPU methods raise `GpuContextError` if called without it. `AesGpuSetup` holds pre-allocated `DeviceBuffer`s for the key schedule and S-boxes — these are uploaded once at construction and reused across all calls.

Multi-block CPU path: `_encrypt_cpu`/`_decrypt_cpu` use a `comptime for` loop over `Size // BLOCK_SIZE` blocks, so the iteration count is unrolled at compile time.

Multi-block GPU path: `grid_dim = num_blocks`, `block_dim = BLOCK_SIZE (16)`. Each GPU thread block processes exactly one AES block, with 16 threads (one per byte) operating on a shared-memory state array.

### CPU cipher (`mojo_crypto/aes/cpu/cipher.mojo`)

Straightforward FIPS 197 implementation. State layout is column-major: `state[r][c] ↔ state[r + 4*c]`. GF(2⁸) multiplication uses Russian-peasant via `multiply`/`xtime`.

### GPU cipher (`mojo_crypto/aes/gpu/cipher.mojo`)

Each thread handles one byte (`thread_idx.x` = local byte index, `block_idx.x` = AES block index). State lives in `AddressSpace.SHARED`. `shift_rows` and `mix_columns` require `barrier()` calls to prevent read-after-write races between threads in the same block.

### Key expansion (`mojo_crypto/aes/expand.mojo`)

FIPS 197 Algorithm 2. Parameterised by `[WordsSize, Nk, KeySize]`. `Nk = KeySize/4`, `WordsSize = Nb*(Nr+1)`.

### Test vectors (`tests/aes/`)

NIST KAT and MCT `.rsp` files are loaded via a Python helper (`tests/aes/load_test_vectors.py`). `utils.mojo` bridges Mojo and Python via `std.python`. Tests cover both CPU and GPU paths with the same vectors.

### Known GPU performance issues

`docs/gpu-performance-review.md` documents outstanding GPU bottlenecks in priority order: warp divergence in `multiply`, global-memory S-box/key-schedule accesses, and only 16 threads per block (half a warp). Consult that document before working on GPU optimisations.
