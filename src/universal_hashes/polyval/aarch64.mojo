from std.memory import bitcast
from std.sys.intrinsics import llvm_intrinsic

from .common import (
    BLOCK_SIZE,
    KEY_SIZE,
    TAG_SIZE,
)
from .rf import _PolyvalRf, Pmull

comptime PolyvalAarch64 = _PolyvalRf[_Pmull]
"""POLYVAL using ARMv8 Crypto Extension PMULL for the 64×64→128-bit multiply."""


struct _Pmull(Pmull):
    @staticmethod
    def mul(a: UInt64, b: UInt64) -> SIMD[DType.uint64, 2]:
        """
        64×64 → 128-bit polynomial multiply (PMULL).

        llvm.aarch64.neon.pmull64: (i64, i64) -> <16 x i8>  (IntrinsicsAArch64.td)

        `a`/`b` are routed through 1-lane vectors (rather than passed as bare
        scalars) so the backend selects the operands from FPR registers, which
        is what the ISel patterns for this intrinsic expect.
        """

        var va = SIMD[DType.uint64, 1](a)
        var vb = SIMD[DType.uint64, 1](b)
        var result = llvm_intrinsic[
            "llvm.aarch64.neon.pmull64", SIMD[DType.uint8, 16]
        ](va, vb)
        return bitcast[DType.uint64, 2](result)
