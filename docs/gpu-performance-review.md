# GPU AES Performance Review

## Summary

The current GPU implementation is functionally correct but has critical structural
issues that prevent it from delivering any real throughput advantage over the CPU path.
Issues are grouped by severity.

---

## Critical

### 1. Buffers and constants re-allocated on every call (`aes.mojo:43–48`, `69–74`)

Every `encrypt` / `decrypt` call allocates three device buffers and copies the key
schedule and S-box to GPU memory from scratch:

```
var block_in = ctx.enqueue_create_buffer[DType.uint8](BLOCK_SIZE)   # alloc
var w        = ctx.enqueue_create_buffer[DType.uint32](Self.WordsSize) # alloc
var sbox     = ctx.enqueue_create_buffer[DType.uint32](256)           # alloc
block_in.enqueue_copy_from(block)   # H→D copy
w.enqueue_copy_from(self.w)         # H→D copy (key schedule — constant!)
sbox.enqueue_copy_from(SBOX.unsafe_ptr())  # H→D copy (S-box — constant!)
```

The key schedule and both S-boxes are immutable after construction.
Allocating and uploading them on every call makes the GPU version strictly worse
than CPU for small workloads.

**Fix:** Add `w_dev`, `sbox_dev`, `sbox_inv_dev` as fields on `Aes`, upload in
`__init__`, reuse across calls.

---

### 2. Only 16 threads per block — half a warp (`gpu/cipher.mojo:23`, `aes.mojo:56`)

`block_dim=BLOCK_SIZE=16`. A GPU warp is 32 threads; 16 threads is half a warp,
meaning the other 16 lanes in every scheduled warp are idle slots. The SM
scheduler cannot hide latency with so few in-flight warps, and occupancy is
effectively zero.

**Fix:** Process multiple AES blocks per thread block. Map 1 thread → 1 byte of
1 block, pack N blocks per thread block → `block_dim = N * 16`. A natural value
is `N=8` (128 threads, 4 warps) or `N=16` (256 threads, 8 warps).

---

### 3. `multiply` is a data-dependent loop on the GPU (`gpu/cipher.mojo:220–229`)

```mojo
def multiply(a: UInt8, b: UInt8) -> UInt8:
    while scalar != 0:   # ← variable iteration count per thread
        ...
```

Loop iterations depend on the input value. Different threads in the same warp
iterate different numbers of times, causing **warp divergence**: the hardware
serialises every distinct branch path. In `mix_columns` this runs up to 8 times
per byte per round.

**Fix:** Replace with a 256-entry precomputed lookup table (`MUL2`, `MUL3`,
`MUL9`, `MUL11`, `MUL13`, `MUL14`) stored in shared memory. One table lookup
per multiply, no branches, no divergence.

---

## High

### 4. S-box and key schedule accessed from global memory every round

`sbox`, `sbox_inv`, and `w` are `DeviceBuffer` raw pointers — global memory.
Every `sub_bytes` call (`sbox[Int(state[i])]`) and every `add_round_key` call
hits global memory with an uncoalesced, index-dependent load.

**Fix:**
- Load `sbox` (1 KB) and `w` (≤ 240 B) into **shared memory** at kernel start,
  barrier once, then use them from shared for all rounds.
- Alternatively, `sbox` is read-only and fits in constant cache — mark the
  pointer with the appropriate address space.

---

### 5. One block processed per launch — no batching (`aes.mojo:39`, `65`)

The public API takes a single `InlineArray[UInt8, BLOCK_SIZE]` per call.
Even with `BLOCKS_PER_GRID > 1`, all blocks encrypt the same input because
there is only one block buffer. The overhead of a kernel launch (µs range) vastly
exceeds the work of one 16-byte AES block.

**Fix:** Change the API to accept a slice / buffer of N blocks:
```
def encrypt[BLOCKS_PER_GRID: Int](
    self, ctx: DeviceContext,
    blocks: UnsafePointer[Scalar[DType.uint8], MutAnyOrigin],
    n_blocks: Int,
) raises
```
Each grid block processes one AES block; `grid_dim = n_blocks`, `block_dim = 16`.

---

## Medium

### 6. Two barriers per `shift_rows` / `mix_columns` (`gpu/cipher.mojo:121–123`, `158–167`)

With only 16 threads and a shared-memory state of 16 bytes, barriers are
necessary for correctness. But the barrier count doubles once `mix_columns` also
needs them. At higher occupancy (after fix #2) these barriers still serialize
within a block — they cannot be avoided, but their cost is amortised over more
useful work.

**Fix:** After packing N blocks per thread block (fix #2), each block's 16
threads are contiguous in a warp-sub-group; within-warp synchronisation via
`warp.shuffle_*` can replace shared-memory barriers for `shift_rows`, removing
two barriers per round entirely.

---

### 7. Duplicate import in `gpu/cipher.mojo` (`line 5`)

```mojo
from ..common import Nb, BLOCK_SIZE, BLOCK_LAYOUT, BLOCK_LAYOUT
#                                    ^^^^^^^^^^^^^  ^^^^^^^^^^^^^ — imported twice
```

Minor, but `BLOCK_LAYOUT` is also not used in this file.

---

## Plan

| Priority | Task | File(s) |
|----------|------|---------|
| 1 | Pre-allocate `w_dev`, `sbox_dev`, `sbox_inv_dev` in `Aes.__init__`; remove per-call alloc/copy | `aes.mojo` |
| 2 | Change public GPU API to accept N-block buffer; `grid_dim=n_blocks`, `block_dim=16` | `aes.mojo`, `block_cipher.mojo` |
| 3 | Pack N AES blocks per thread block (e.g. N=16); `block_dim=N*16`, state shared array of `N*16` bytes | `gpu/cipher.mojo` |
| 4 | Load `sbox` + `w` into shared memory at kernel entry; single barrier before first use | `gpu/cipher.mojo` |
| 5 | Replace `multiply` loop with precomputed GF tables in shared memory | `gpu/cipher.mojo` |
| 6 | Explore replacing `shift_rows` barriers with warp shuffles (after N-block packing) | `gpu/cipher.mojo` |
| 7 | Remove duplicate `BLOCK_LAYOUT` import | `gpu/cipher.mojo` |
