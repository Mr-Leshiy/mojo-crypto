# AES Implementation Plan: Reaching RustCrypto Parity

## Current State

| Dimension | Current | RustCrypto |
|---|---|---|
| Software cipher | FIPS 197 scalar, lookup-table S-box | Fixsliced (bitwise, no tables) |
| x86 acceleration | None | AES-NI + VAES256 (30 blocks) + VAES512 (64 blocks) |
| ARM acceleration | None | ARMv8 Crypto Extension (`vaeseq_u8` etc.) |
| Constant-time | No (S-box table lookup is cache-timing-observable) | Yes (fixsliced backend) |
| Parallel CPU blocks | No | Yes — encrypt_par / decrypt_par on all backends |
| Inverse key schedule | Computed on-the-fly per round | Precomputed at key init for decryption |
| Architecture dispatch | None | Compile-time + runtime autodetect |
| GPU | 16-thread/block CUDA kernel | N/A |
| Hazmat API | None | Raw round operations, mix_columns |

The single biggest gap is hardware acceleration: AES-NI and ARMv8 Crypto are
10–30× faster than any software path and are present on virtually all modern
x86-64 and Apple/server ARM hardware.

---

## Roadmap

### Phase 1 — ARMv8 Crypto Extension backend (priority: this machine is aarch64)

**New file:** `mojo_crypto/aes/cpu/armv8.mojo`

The ARMv8 Crypto Extension maps to LLVM intrinsics that are already confirmed
working in this environment (tested above):

```
llvm.aarch64.crypto.aese   — SubBytes + ShiftRows + AddRoundKey (one round)
llvm.aarch64.crypto.aesmc  — MixColumns
llvm.aarch64.crypto.aesd   — inverse SubBytes + ShiftRows + AddRoundKey
llvm.aarch64.crypto.aesimc — inverse MixColumns
```

All four operate on `SIMD[DType.uint8, 16]`.

**Key schedule:** the existing pure-SW `key_expansion` in `expand.mojo` is
correct and used unchanged. ARMv8 has no hardware key-schedule assist (unlike
x86 `aeskeygenassist`), so software expansion is the standard approach for ARM
too.

**Decryption key schedule:** RustCrypto precomputes `inv_mix_columns` on the
intermediate round keys at init time so each decrypt call avoids that cost.
We should do the same: add an `InlineArray[UInt32, WordsSize]` for the
equivalent-inverse-cipher key schedule.

**Encrypt (single block):**
```
state = plaintext as SIMD[uint8, 16]
for r in 0..(Nr-1):
    state = aese(state, round_key[r])   # SubBytes + ShiftRows + XOR key
    state = aesmc(state)                 # MixColumns
state = aese(state, round_key[Nr-1])    # final round without MixColumns
state ^= round_key[Nr]                  # final AddRoundKey
```

Note: `aese` performs `AddRoundKey` with the provided argument before the
S-box, so round keys are XOR-ed in shifted by one position vs. FIPS order.
This is the standard ARM AES idiom; see ARM ISA manual §C7.2.5.

**Decrypt:** mirror with `aesd` / `aesimc`, using the precomputed inverse
round keys.

**Parallel blocks:** process N blocks by holding N independent
`SIMD[DType.uint8, 16]` values and issuing the same round key to all. The
out-of-order core pipelines them with zero overhead. Start with 8 parallel
(covers a full AES-CTR/CBC-MAC stripe); tune later.

**Files to create/modify:**
- `mojo_crypto/aes/cpu/armv8.mojo` — new backend
- `mojo_crypto/aes/aes.mojo` — dispatch to armv8 backend when available
- `mojo_crypto/aes/cpu/__init__.mojo` — re-export

---

### Phase 2 — x86 AES-NI backend

**New file:** `mojo_crypto/aes/cpu/ni.mojo`

LLVM intrinsics (all operate on `SIMD[DType.uint64, 2]` which is the Mojo
representation of an `__m128i`):

```
llvm.x86.aesni.aesenc         — one middle round (encrypt)
llvm.x86.aesni.aesenclast     — final round (encrypt)
llvm.x86.aesni.aesdec         — one middle round (decrypt)
llvm.x86.aesdeclast           — final round (decrypt)
llvm.x86.aesni.aeskeygenassist — key schedule assist
llvm.x86.aesni.aesimc         — inverse MixColumns for decrypt key schedule
```

**Key schedule:** replace the current pure-SW `expand.mojo` for x86 with the
`aeskeygenassist`-based approach from RustCrypto `ni/expand.rs`. The
hardware-assisted version is both faster and well-validated. The existing
pure-SW path stays as the fallback.

**Encrypt (single block):**
```
state ^= round_key[0]
for r in 1..(Nr):
    state = aesenc(state, round_key[r])
state = aesenclast(state, round_key[Nr])
```

**Decrypt:** use the equivalent inverse cipher (EIC) key schedule: apply
`aesimc` to inner round keys at key-init time, then `aesdec` + `aesdeclast`
at encrypt time. Same approach as RustCrypto `ni/encdec.rs`.

**Parallel blocks:** unroll 8 blocks per call (AES-NI latency is ~4 cycles,
throughput ~1 cycle/block when 4+ are in flight). RustCrypto uses up to
30 blocks for VAES256; 8 is a good starting point for plain AES-NI.

**Files to create/modify:**
- `mojo_crypto/aes/cpu/ni.mojo` — new backend
- `mojo_crypto/aes/cpu/expand_ni.mojo` — hardware-assisted key expansion
- `mojo_crypto/aes/aes.mojo` — dispatch

---

### Phase 3 — Compile-time architecture dispatch

**Modify:** `mojo_crypto/aes/aes.mojo`

Use `CompilationTarget` (confirmed importable from `std.sys`) to select the
backend at comptime:

```mojo
from std.sys import CompilationTarget

comptime _USE_ARMV8 = CompilationTarget.host_compilation_target.is_aarch64()
    and CompilationTarget.host_compilation_target.has_feature("aes")
comptime _USE_NI    = CompilationTarget.host_compilation_target.is_x86()
    and CompilationTarget.host_compilation_target.has_feature("aes")
```

Note: the exact `CompilationTarget` API is still stabilizing in Mojo 1.0.0b1.
The `has_feature` method name needs to be verified against the current stdlib
source before use. If it is not yet exposed, use `@parameter if` with
`is_aarch64()` / `is_x86()` as a first pass and add feature gating later.

The `Aes[KeySize]` struct remains the single public type; the backend is
selected internally and invisible to callers. This matches RustCrypto's design.

**Files to modify:**
- `mojo_crypto/aes/aes.mojo`
- `mojo_crypto/block_cipher.mojo` — add `encrypt_par` / `decrypt_par` to both
  traits (see Phase 4)

---

### Phase 4 — Parallel block API

**Modify:** `mojo_crypto/block_cipher.mojo` and `mojo_crypto/aes/aes.mojo`

Add parallel variants to the `BlockCipher` trait:

```mojo
trait BlockCipher:
    def encrypt[Size: Int](self, mut data: InlineArray[UInt8, Size]):
        ...
    def decrypt[Size: Int](self, mut data: InlineArray[UInt8, Size]):
        ...
    # New: process N independent blocks in one call
    def encrypt_par[N: Int](self, mut blocks: InlineArray[InlineArray[UInt8, 16], N]):
        ...
    def decrypt_par[N: Int](self, mut blocks: InlineArray[InlineArray[UInt8, 16], N]):
        ...
```

Alternatively (simpler to start): keep a flat `InlineArray[UInt8, Size]` but
have the backend implementations process `Size // 16` blocks at a time using
SIMD register parallelism instead of a scalar loop.

The current `_encrypt_cpu` / `_decrypt_cpu` loop in `aes.mojo` becomes the
dispatch point: the hardware backends process multiple blocks per iteration
while the software fallback keeps its current scalar loop.

---

### Phase 5 — Constant-time software fallback (fixsliced)

**New file:** `mojo_crypto/aes/cpu/soft.mojo`

Replace the current lookup-table S-box path with a fixsliced implementation
based on [Fixslicing: A New GIFT Representation (Adomnicai & Peyrin,
IACR 2020/1123)](https://eprint.iacr.org/2020/1123.pdf) as used by RustCrypto.

Fixslicing performs SubBytes via bitwise logic over a rearranged state
representation — no table lookups, no data-dependent memory accesses, no
cache-timing side channels.

This is a significant implementation effort (the RustCrypto fixslice64.rs is
~1400 lines). Defer until Phase 1–4 are complete and benchmarked.

**Security note:** until this phase is done, the current implementation is
**not constant-time** and must not be used in contexts where a side-channel
adversary can observe cache behaviour (e.g. shared-cache VMs, SGX).

---

### Phase 6 — GPU optimizations (existing CUDA path)

The `docs/gpu-performance-review.md` already documents these in priority order.
After Phase 1–3 land, re-benchmark to confirm which bottlenecks remain relevant
given that CPU throughput will have improved dramatically.

Key items from that document (summarised here for completeness):
1. Replace GF `multiply` loop with a lookup table in shared memory — eliminates
   warp divergence
2. Move S-box and key schedule to `AddressSpace.CONSTANT` — hardware cache vs.
   L2 global
3. Increase occupancy: current 16 threads/block is half a warp; consider
   fusing 2 AES blocks per thread block (32 threads) or using cooperative
   groups

---

## File Layout After All Phases

```
mojo_crypto/
  block_cipher.mojo          — traits: BlockCipher, GpuBlockCipher (+ encrypt_par)
  errors.mojo
  aes/
    PLAN.md                  — this file
    common.mojo              — Nb, BLOCK_SIZE, SBOX, SBOX_INV
    expand.mojo              — pure-SW FIPS 197 key expansion (unchanged)
    aes.mojo                 — Aes[KeySize] struct + comptime backend dispatch
    cpu/
      cipher.mojo            — current pure-SW scalar backend (soft fallback)
      armv8.mojo             — Phase 1: ARMv8 Crypto Extension backend
      ni.mojo                — Phase 2: x86 AES-NI backend
      expand_ni.mojo         — Phase 2: aeskeygenassist key expansion
      soft.mojo              — Phase 5: fixsliced constant-time backend
    gpu/
      cipher.mojo            — CUDA backend (Phase 6 optimisations)
```

---

## Testing Strategy

- All new backends must pass the existing NIST KAT and MCT vectors in
  `tests/aes/test_aes.mojo` — no new test infrastructure needed for
  correctness.
- Add a multi-block round-trip test for the parallel API (Phase 4).
- Add a benchmark entry in `benchmarks/aes/bench.mojo` for each new backend
  so throughput regressions are visible.
- The `pixi run test` / `pixi run bench` commands remain the entry points.

---

## Expected Performance After Phase 1–2

Based on RustCrypto benchmarks and publicly available AES-NI data:

| Path | Approx. throughput |
|---|---|
| Current scalar (this code) | ~50–150 MB/s |
| ARMv8 Crypto (single block) | ~1–2 GB/s |
| ARMv8 Crypto (8 blocks parallel) | ~5–8 GB/s |
| x86 AES-NI (single block) | ~700 MB/s–1 GB/s |
| x86 AES-NI (8 blocks parallel) | ~3–5 GB/s |

Numbers are single-core, AES-128, CTR-equivalent throughput. Actual results
depend on clock speed and pipeline depth; the benchmark suite will give precise
numbers for this hardware.
