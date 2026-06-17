from std.sys.intrinsics import llvm_intrinsic

from mojo_crypto.universal_hashes.traits import UniversalHashable
from .field_element import FieldElement
from .expanded_key import ExpandedKey
from .common import BLOCK_SIZE, KEY_SIZE, TAG_SIZE, P1


struct PolyvalX86(Copyable, ImplicitlyDestructible, Movable, UniversalHashable):
    """
    VPCLMULQDQ optimized POLYVAL implementation using R/F Algorithm
    Adapted from the implementation in the Apache 2.0 + MIT-licensed HPCrypt library
    Copyright (c) 2024 HPCrypt Contributors

    Uses the R/F algorithm from "Efficient GHASH Implementation Using CLMUL":
    - 4 CLMULs per block for multiplication (R and F terms)
    - 1 CLMUL for reduction (Lemma 3)
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

    The lane swap turns [H0:H1] into [H1:H0]; _pclmul64(H0, P1) is the
    carry-less product of the low lane against the reduction constant.
    """

    h_swap = SIMD[DType.uint64, 2](h[1], h[0])
    t = _pclmul64(h[0], P1)
    return h_swap ^ t


@always_inline
def _gf128_mul_rf(
    m: SIMD[DType.uint64, 2],
    h: SIMD[DType.uint64, 2],
    d: SIMD[DType.uint64, 2],
) -> SIMD[DType.uint64, 2]:
    """Complete R/F multiplication with reduction (5 PCLMULQDQs total)."""

    rf = _rf_mul_unreduced(m, h, d)
    return _reduce_rf(rf[0], rf[1])


@always_inline
def _rf_mul_unreduced(
    m: SIMD[DType.uint64, 2],
    h: SIMD[DType.uint64, 2],
    d: SIMD[DType.uint64, 2],
) -> Tuple[SIMD[DType.uint64, 2], SIMD[DType.uint64, 2]]:
    """
    R/F multiplication: compute R and F terms without reduction (4 PCLMULQDQs).

    R = M0×D1 ⊕ M1×H1
    F = M0×D0 ⊕ M1×H0
    """

    r = _pclmul64(m[0], d[1]) ^ _pclmul64(m[1], h[1])
    f = _pclmul64(m[0], d[0]) ^ _pclmul64(m[1], h[0])
    return (r, f)


@always_inline
def _reduce_rf(
    r: SIMD[DType.uint64, 2], f: SIMD[DType.uint64, 2]
) -> SIMD[DType.uint64, 2]:
    """
    Reduction using Lemma 3: Result = R ⊕ F1 ⊕ (x^64×F0) ⊕ (P1×F0)  (1 PCLMULQDQ).

    F1 is the high lane of f; x^64×F0 shifts F0 into the high lane.
    """

    f1_vec = SIMD[DType.uint64, 2](f[1], 0)
    f0_shifted = SIMD[DType.uint64, 2](0, f[0])
    return r ^ f1_vec ^ f0_shifted ^ _pclmul64(f[0], P1)


@always_inline
def _pclmul64(a: UInt64, b: UInt64) -> SIMD[DType.uint64, 2]:
    """
    64×64 → 128-bit carry-less multiply (PCLMULQDQ).

    llvm.x86.pclmulqdq: (<2 x i64>, <2 x i64>, i8 imm) -> <2 x i64>  (IntrinsicsX86.td)
    The i8 immediate selects which 64-bit half of each operand is multiplied
    (bit 0 picks the half of arg0, bit 4 the half of arg1). Placing a and b in
    lane 0 of each operand and passing 0x00 selects low×low — matching the
    scalar (i64, i64) interface of AArch64's _pmull64.
    """

    va = SIMD[DType.uint64, 2](a, 0)
    vb = SIMD[DType.uint64, 2](b, 0)
    return llvm_intrinsic["llvm.x86.pclmulqdq", SIMD[DType.uint64, 2]](
        va, vb, Int8(0x00)
    )
