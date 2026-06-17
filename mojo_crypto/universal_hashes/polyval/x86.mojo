from std.sys.intrinsics import llvm_intrinsic

from mojo_crypto.universal_hashes.traits import UniversalHashable
from .field_element import FieldElement
from .common import (
    BLOCK_SIZE,
    KEY_SIZE,
    TAG_SIZE,
    P1,
    ExpandedKey,
    load_bytes,
    store_bytes,
    gf128_mul_rf,
)


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

    var _h: ExpandedKey[_pclmul64]
    var _y: FieldElement

    def __init__(out self, h: InlineArray[UInt8, Self.KEY_SIZE]):
        self._h = ExpandedKey[_pclmul64](h)
        self._y = FieldElement.zeros()

    def update_block(mut self, block: InlineArray[UInt8, Self.BLOCK_SIZE]):
        """Absorb one block into the accumulator: y = (y ⊕ block) × H."""
        data = load_bytes(block)
        y = load_bytes(self._y._v)
        h1 = load_bytes(self._h.h1._v)
        d1 = load_bytes(self._h.d1._v)

        # XOR with accumulator
        acc = y ^ data

        # Multiply by H using R/F algorithm
        self._y = FieldElement(
            store_bytes(gf128_mul_rf[_pclmul64](acc, h1, d1))
        )

    def finalize(var self) -> InlineArray[UInt8, Self.TAG_SIZE]:
        return self._y._v


@parameter
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
