# LLVM AArch64 crypto AES intrinsics.
#
# LLVM AArch64 intrinsic definitions (no separate doc page exists; .td is authoritative):
#   https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/IR/IntrinsicsAArch64.td


from std.sys import CompilationTarget
from std.sys.intrinsics import llvm_intrinsic

from ..common import Nb, BLOCK_SIZE


# AESE: AddRoundKey(state XOR key), SubBytes, ShiftRows → next-round state.
# Note: AESE fuses AddRoundKey into the instruction — key is XOR'd before the
# S-box, not after. This produces the "lag-by-one" key schedule used in cipher().
@always_inline
def _aese(
    state: SIMD[DType.uint8, BLOCK_SIZE], key: SIMD[DType.uint8, BLOCK_SIZE]
) -> SIMD[DType.uint8, BLOCK_SIZE]:
    return llvm_intrinsic[
        "llvm.aarch64.crypto.aese", SIMD[DType.uint8, BLOCK_SIZE]
    ](state, key)


# AESMC: MixColumns on the output of AESE.
@always_inline
def _aesmc(
    state: SIMD[DType.uint8, BLOCK_SIZE]
) -> SIMD[DType.uint8, BLOCK_SIZE]:
    return llvm_intrinsic[
        "llvm.aarch64.crypto.aesmc", SIMD[DType.uint8, BLOCK_SIZE]
    ](state)


# AESD: AddRoundKey(state XOR key), InvSubBytes, InvShiftRows → next-round state.
@always_inline
def _aesd(
    state: SIMD[DType.uint8, BLOCK_SIZE], key: SIMD[DType.uint8, BLOCK_SIZE]
) -> SIMD[DType.uint8, BLOCK_SIZE]:
    return llvm_intrinsic[
        "llvm.aarch64.crypto.aesd", SIMD[DType.uint8, BLOCK_SIZE]
    ](state, key)


# AESIMC: InvMixColumns — used to convert encrypt round keys to the
# equivalent-inverse schedule (see expand_round_keys_inv).
@always_inline
def _inv_mix(v: SIMD[DType.uint8, BLOCK_SIZE]) -> SIMD[DType.uint8, BLOCK_SIZE]:
    return llvm_intrinsic[
        "llvm.aarch64.crypto.aesimc", SIMD[DType.uint8, BLOCK_SIZE]
    ](v)


# FIPS 197 §5.1 Cipher() via ARMv8 Crypto Extension.
def cipher[
    Nr: Int, o: MutOrigin
](data: Span[UInt8, o], rks: InlineArray[SIMD[DType.uint8, 16], Nr + 1]):
    var s = data.unsafe_ptr().load[width=BLOCK_SIZE]()
    comptime for r in range(Nr - 1):
        s = _aesmc(_aese(s, rks[r]))
    s = _aese(s, rks[Nr - 1])
    s ^= rks[Nr]
    data.unsafe_ptr().store(s)


# FIPS 197 §5.3 InvCipher() via ARMv8 Crypto Extension (equivalent inverse).
def decipher[
    Nr: Int, o: MutOrigin
](data: Span[UInt8, o], rks: InlineArray[SIMD[DType.uint8, 16], Nr + 1]):
    var s = data.unsafe_ptr().load[width=BLOCK_SIZE]()
    s = _aesd(s, rks[0])
    s = _inv_mix(s)
    comptime for r in range(1, Nr - 1):
        s = _aesd(s, rks[r])
        s = _inv_mix(s)
    s = _aesd(s, rks[Nr - 1])
    s ^= rks[Nr]
    data.unsafe_ptr().store(s)
