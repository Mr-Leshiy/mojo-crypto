# GPU AES Performance Review

## Summary

The GPU implementation in `mojo_crypto/aes/gpu/cipher.mojo` is functionally correct
(it passes the KAT and MCT vectors) but its kernel design is the *fine-grained* AES
mapping — **16 threads per block, one thread per state byte**, with the 16-byte state
held in shared memory and `barrier()` calls between every step. This is the slow
design. The literature on GPU AES (e.g. *Optimizing AES on GPU*,
[arXiv:1902.05234](https://arxiv.org/pdf/1902.05234), and Manavski 2007) converges
on a *coarse-grained* design: **one thread per 16-byte block**, the round computed
with **T-tables** that fuse SubBytes + ShiftRows + MixColumns into table lookups,
state kept in registers, no barriers, and no runtime GF(2⁸) multiplication.

The single highest-impact change is to adopt that T-table / one-block-per-thread
architecture. It simultaneously removes the three biggest current bottlenecks:
warp divergence in `multiply`, the `barrier()` pairs, and the half-warp occupancy
problem. Everything else is secondary.

## Already addressed (do not re-report)

These were issues in earlier revisions and have since been fixed — they are listed
so this document is not mistaken for current state:

- **Per-call buffer allocation** — the key schedule and S-boxes are now uploaded
  once in `AesGpuSetup.__init__` (`aes/aes.mojo`) and reused across calls.
- **Single-block-per-launch API** — the public API now takes
  `InlineArray[UInt8, Size]` for any block-aligned `Size`; the GPU path launches
  `grid_dim = Size // BLOCK_SIZE` blocks (`aes/aes.mojo` `_encrypt_gpu`/`_decrypt_gpu`).
- **Duplicate `BLOCK_LAYOUT` import** — gone; the file now imports only
  `Nb, BLOCK_SIZE`.

---

## Critical

### 1. Runtime GF(2⁸) multiply is a data-dependent loop → warp divergence (`gpu/cipher.mojo:222`)

```mojo
def multiply(a: UInt8, b: UInt8) -> UInt8:
    while scalar != 0:        # ← iteration count depends on `a`
        if scalar & 1:        # ← per-lane branch
            result ^= factor
        factor = xtime(factor)
        scalar >>= 1
    return result
```

The loop trip count and the inner branch both depend on the operand, so lanes in a
warp take different paths and the hardware serializes them. `mix_columns` /
`inv_mix_columns` call `multiply` up to 4× per output byte, every round.

**Fix:** Eliminate runtime multiplication entirely. The T-table approach (see
*Recommended architecture* below) folds every `xtime`/`multiply` into precomputed
tables. If keeping the explicit MixColumns for now, at minimum replace `multiply`
with constant `MUL2/MUL3/MUL9/MUL11/MUL13/MUL14` lookup tables — branchless, no
divergence.

### 2. Fine-grained mapping: 16 threads/block, half a warp (`gpu/cipher.mojo:23-24`, `aes/aes.mojo` `block_dim=BLOCK_SIZE`)

Each thread owns one byte; a thread block is 16 threads. A warp is 32 lanes, so
every launched warp runs at most half-occupied, and the per-block shared state forces
synchronization. The paper (§4.1) and Manavski both map **one thread → one full
16-byte state**, which needs no intra-block coordination and lets a block hold
32/64/128 *independent* states (1/2/4 warps fully packed).

**Fix:** Switch to one-block-per-thread. `block_dim` becomes the number of AES
blocks per thread block (e.g. 128 or 256), `grid_dim = ceil(num_blocks / block_dim)`,
and each thread loads its 16 bytes into registers and runs the full cipher locally.

### 3. Per-step `barrier()` pairs (`gpu/cipher.mojo:123-125, 139-141, 160-169, 188-217`)

`shift_rows`, `inv_shift_rows`, `mix_columns`, `inv_mix_columns` each issue two
`barrier()` calls because threads share the state through shared memory. Barriers
stall the whole block and exist *only* because of the fine-grained mapping.

**Fix:** They disappear under the one-block-per-thread design — a thread owns its
entire state in registers, so there is no cross-thread dependency to synchronize.

---

## Recommended architecture (from arXiv:1902.05234 §3.2.3, §4)

This is the target the three critical items above all point toward.

### T-tables fuse SubBytes + ShiftRows + MixColumns

Precompute four 256-entry, 4-byte tables `T0..T3` where each entry is the S-box
output of one byte spread across a column and pre-multiplied by the MixColumns
coefficients. A full round for output column *j* becomes:

```
e_j = T0[a0_j] ^ T1[a1_{j+1}] ^ T2[a2_{j+2}] ^ T3[a3_{j+3}] ^ k_j
```

— four loads and four XORs per column, **no GF multiply, no separate ShiftRows
write, no intermediate shared-memory state.** The last round (no MixColumns) uses
the plain S-box, so keep the existing `SBOX`/`SBOX_INV` for it. Decryption uses the
inverse tables `Td0..Td3` built from `SBOX_INV` and the inverse MixColumns
coefficients (0x09/0x0b/0x0d/0x0e).

### Table placement: shared memory for T-tables, constant for round keys

The paper (§4.2–4.3) puts both T-tables and round keys in **constant memory**.
That is ideal for round keys — every lane in a warp reads the *same* key word, which
constant memory broadcasts in one transaction. But T-table lookups are
**data-dependent** (each lane indexes a different entry), and constant memory
*serializes* divergent addresses within a warp. So:

- **Round keys → constant memory** (uniform access, broadcast).
- **T-tables → shared memory**, copied from global at kernel entry with a single
  barrier before first use. Watch for **bank conflicts**: a 256×4B table is 1 KB =
  256 banks' worth; byte-indexed random lookups will conflict. Mitigations used in
  the literature: replicate the table once per warp, or pad/​interleave so each
  lane's stream hits distinct banks.
- **State / plaintext → registers** (per §4.1, "the plaintext is stored in the
  thread's register").

### Memory coalescing (not covered by the paper, but matters here)

The *current* byte-per-thread load `in_out[block_idx.x*16 + thread_idx.x]` is
naturally coalesced (consecutive lanes → consecutive bytes). When moving to
one-block-per-thread, a naive `in_out[16*tid + k]` makes lane *t* and *t+1* read
16 bytes apart — **uncoalesced**. Restore coalescing by treating the input as
`UInt32` words and having each warp load words in a transposed/interleaved layout
(word *k* of all 32 states contiguous), or load 16-byte vectors. Measure with a
profiler; uncoalesced global loads can erase the gains from the T-table change.

---

## Medium

### 4. S-box stored as `UInt32` (1 KB) instead of `UInt8` (256 B) (`aes/common.mojo`)

`SBOX` is `InlineArray[UInt32, 256]` so `sub_word` can shift without a widening cast
on the CPU key-expansion path. On the GPU this quadruples the table footprint in
whatever memory space it lands in, hurting cache/shared-memory residency. Once the
GPU path uses T-tables, the only S-box use on-device is the final round; consider a
`UInt8` device copy for that to keep the on-device footprint at 256 B.

### 5. Host↔device transfer is synchronous, no overlap (`aes/aes.mojo` `_encrypt_gpu`/`_decrypt_gpu`)

Each call does H→D copy, kernel, D→H copy in order with no streaming. For large
buffers, splitting into chunks and overlapping copy with compute via multiple
streams (and pinned host memory) hides transfer latency. The paper notes GPU only
wins above ~4 KB because of fixed launch/transfer overhead — overlap pushes that
crossover down. Lower priority than the kernel redesign.

---

## Plan

| Priority | Task | File(s) |
|----------|------|---------|
| 1 | Build `T0..T3` (and inverse `Td0..Td3`) encryption tables; replace separate SubBytes/ShiftRows/MixColumns with table-lookup rounds | `gpu/cipher.mojo`, `aes/common.mojo` |
| 2 | Switch to one-thread-per-block mapping; state in registers; drop all `barrier()` calls; `block_dim` = blocks/threadblock | `gpu/cipher.mojo`, `aes/aes.mojo` |
| 3 | Place round keys in constant memory; stage T-tables into shared memory at kernel entry (mind bank conflicts) | `gpu/cipher.mojo`, `aes/aes.mojo` |
| 4 | Restore coalesced global loads/stores under the new mapping (word-transposed or vectorized access) | `gpu/cipher.mojo`, `aes/aes.mojo` |
| 5 | Use a 256 B `UInt8` S-box on device for the final round | `aes/common.mojo`, `gpu/cipher.mojo` |
| 6 | Chunk large buffers across CUDA streams with pinned memory to overlap transfer and compute | `aes/aes.mojo` |
