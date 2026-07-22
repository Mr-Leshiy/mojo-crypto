from std.sys.intrinsics import llvm_intrinsic

from mojo_crypto.universal_hashes.traits import UniversalHashable
from ._common import (
    BLOCK_SIZE,
    KEY_SIZE,
    TAG_SIZE,
)
from .rf import PolyvalRf, Pmull

comptime PolyvalX86 = PolyvalRf[_Pmull]


struct _Pmull(Pmull):
    @staticmethod
    def mul(a: UInt64, b: UInt64) -> SIMD[DType.uint64, 2]:
        """
        64×64 → 128-bit carry-less multiply (PCLMULQDQ).

        llvm.x86.pclmulqdq: (<2 x i64>, <2 x i64>, i8 imm) -> <2 x i64>  (IntrinsicsX86.td)
        The i8 immediate selects which 64-bit half of each operand is multiplied
        (bit 0 picks the half of arg0, bit 4 the half of arg1). Placing a and b in
        lane 0 of each operand and passing 0x00 selects low×low — matching the
        scalar (i64, i64) interface of AArch64's PMULL.
        """

        va = SIMD[DType.uint64, 2](a, 0)
        vb = SIMD[DType.uint64, 2](b, 0)
        return llvm_intrinsic["llvm.x86.pclmulqdq", SIMD[DType.uint64, 2]](
            va, vb, Int8(0x00)
        )
