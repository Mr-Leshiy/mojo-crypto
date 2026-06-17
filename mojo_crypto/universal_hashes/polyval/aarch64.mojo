from std.sys.intrinsics import llvm_intrinsic

from mojo_crypto.universal_hashes.traits import UniversalHashable
from .field_element import FieldElement
from .expanded_key import ExpandedKey
from .common import BLOCK_SIZE, KEY_SIZE, TAG_SIZE


struct PolyvalAarch64(
    Copyable, ImplicitlyDestructible, Movable, UniversalHashable
):
    """
    ARMv8 NEON + PMULL optimized POLYVAL implementation using R/F Algorithm

    Adapted from the implementation in the Apache 2.0 + MIT-licensed HPCrypt library
    Copyright (c) 2024 HPCrypt Contributors

    This implementation uses the R/F (Reduction/Field) algorithm:
    - 4 PMULL per block for R and F terms
    - PMULL-based reduction (1 PMULL) instead of scalar shifts
    - 4-block aggregated processing with single reduction

    Key equations:
    - D = swap(H) ⊕ (H0 × P1)
    - R = M0×D1 ⊕ M1×H1
    - F = M0×D0 ⊕ M1×H0
    - Result = R ⊕ F1 ⊕ (x^64×F0) ⊕ (P1×F0)

    POLYVAL operates in GF(2^128) with polynomial x^128 + x^127 + x^126 + x^121 + 1
    Unlike GHASH, POLYVAL uses little-endian byte ordering (no byte swap needed).

    <https://eprint.iacr.org/2025/2171.pdf>
    """

    comptime BLOCK_SIZE: Int = BLOCK_SIZE
    comptime KEY_SIZE: Int = KEY_SIZE
    comptime TAG_SIZE: Int = TAG_SIZE

    var _h: ExpandedKey
    var _y: FieldElement

    def __init__(out self, h: InlineArray[UInt8, Self.KEY_SIZE]):
        self._h = expand_key(h)
        self._y = FieldElement.zeros()

    def update_block(mut self, block: InlineArray[UInt8, Self.BLOCK_SIZE]):
        """Absorb one block into the accumulator: y = (y ⊕ block) × H."""
        data = _load_bytes(block)
        y = _load_bytes(self._y._v)
        h1 = _load_bytes(self._h.h1._v)
        d1 = _load_bytes(self._h.d1._v)

        # XOR with accumulator
        acc = y ^ data

        # Multiply by H using R/F algorithm
        self._y = FieldElement(_store_bytes(_gf128_mul_rf(acc, h1, d1)))

    def finalize(var self) -> InlineArray[UInt8, Self.TAG_SIZE]:
        return self._y._v

# x^63 + x^62 + x^57 = 0xC200000000000000
comptime P1: UInt64 = 0xC200_0000_0000_0000

def expand_key(h: InlineArray[UInt8, KEY_SIZE]) -> ExpandedKey:
    h1 = _load_bytes(h)
    d1 = _compute_d(h1)

    h2 = _gf128_mul_rf(h1, h1, d1)
    d2 = _compute_d(h2)

    h3 = _gf128_mul_rf(h2, h1, d1)
    d3 = _compute_d(h3)

    h4 = _gf128_mul_rf(h2, h2, d2)
    d4 = _compute_d(h4)

    return ExpandedKey(
        h1=FieldElement(_store_bytes(h1)),
        d1=FieldElement(_store_bytes(d1)),
        h2=FieldElement(_store_bytes(h2)),
        d2=FieldElement(_store_bytes(d2)),
        h3=FieldElement(_store_bytes(h3)),
        d3=FieldElement(_store_bytes(d3)),
        h4=FieldElement(_store_bytes(h4)),
        d4=FieldElement(_store_bytes(d4)),
    )


@always_inline
def _load_bytes(bytes: InlineArray[UInt8, 16]) -> SIMD[DType.uint64, 2]:
    """Load 16 bytes as two 64-bit lanes."""
    return bytes.unsafe_ptr().bitcast[UInt64]().load[width=2]()


@always_inline
def _store_bytes(reg: SIMD[DType.uint64, 2]) -> InlineArray[UInt8, 16]:
    """Store two 64-bit lanes back into 16 bytes."""
    out = InlineArray[UInt8, 16](uninitialized=True)
    out.unsafe_ptr().bitcast[UInt64]().store(reg)
    return out^


@always_inline
def _compute_d(h: SIMD[DType.uint64, 2]) -> SIMD[DType.uint64, 2]:
    """
    Compute D = swap(H) ⊕ (H0 × P1) for the R/F algorithm.

    vextq_u64(h, h, 1) swaps the two lanes: [H0:H1] → [H1:H0].
    vmull_p64(H0, P1) is the PMULL of the low lane against the reduction constant.
    """

    h_swap = SIMD[DType.uint64, 2](h[1], h[0])
    t = _pmull64(h[0], P1)
    return h_swap ^ t


@always_inline
def _gf128_mul_rf(
    m: SIMD[DType.uint64, 2],
    h: SIMD[DType.uint64, 2],
    d: SIMD[DType.uint64, 2],
) -> SIMD[DType.uint64, 2]:
    """Complete R/F multiplication with reduction (5 PMULLs total)."""

    rf = _rf_mul_unreduced(m, h, d)
    return _reduce_rf(rf[0], rf[1])


@always_inline
def _rf_mul_unreduced(
    m: SIMD[DType.uint64, 2],
    h: SIMD[DType.uint64, 2],
    d: SIMD[DType.uint64, 2],
) -> Tuple[SIMD[DType.uint64, 2], SIMD[DType.uint64, 2]]:
    """
    R/F multiplication: compute R and F terms without reduction (4 PMULLs).

    R = M0×D1 ⊕ M1×H1
    F = M0×D0 ⊕ M1×H0
    """

    r = _pmull64(m[0], d[1]) ^ _pmull64(m[1], h[1])
    f = _pmull64(m[0], d[0]) ^ _pmull64(m[1], h[0])
    return (r, f)


@always_inline
def _reduce_rf(
    r: SIMD[DType.uint64, 2], f: SIMD[DType.uint64, 2]
) -> SIMD[DType.uint64, 2]:
    """
    Reduction using Lemma 3: Result = R ⊕ F1 ⊕ (x^64×F0) ⊕ (P1×F0)  (1 PMULL).

    F1 is the high lane of f; x^64×F0 shifts F0 into the high lane.
    """

    f1_vec = SIMD[DType.uint64, 2](f[1], 0)
    f0_shifted = SIMD[DType.uint64, 2](0, f[0])
    return r ^ f1_vec ^ f0_shifted ^ _pmull64(f[0], P1)


@always_inline
def _pmull64(a: UInt64, b: UInt64) -> SIMD[DType.uint64, 2]:
    """
    64×64 → 128-bit polynomial multiply (PMULL).

    llvm.aarch64.neon.pmull64: (i64, i64) -> <16 x i8>  (IntrinsicsAArch64.td)
    """

    var result = llvm_intrinsic[
        "llvm.aarch64.neon.pmull64", SIMD[DType.uint8, 16]
    ](a, b)
    return UnsafePointer(to=result).bitcast[UInt64]().load[width=2]()
