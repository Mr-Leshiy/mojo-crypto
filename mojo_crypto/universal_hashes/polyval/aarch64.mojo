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
        """

        var result = llvm_intrinsic[
            "llvm.aarch64.neon.pmull64", SIMD[DType.uint8, 16]
        ](a, b)
        return bitcast[DType.uint64, 2](result)
