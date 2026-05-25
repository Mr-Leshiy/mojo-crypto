# LLVM X86 AES-NI intrinsics.
#
# LLVM x86 intrinsic definitions (.td is authoritative):
#   https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/IR/IntrinsicsX86.td
# Intel AES-NI reference:
#   https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html#text=aes

from std.sys.intrinsics import llvm_intrinsic

from ..common import BLOCK_SIZE

# All AES-NI instructions use v2i64 in LLVM IR. Round keys are stored as
# SIMD[DType.uint64, 2] so no conversion is needed at call sites; the state
# is bitcast once at load and once at store.


# AESENC: ShiftRows + SubBytes + MixColumns + AddRoundKey(rk).
@always_inline
def _aesenc(
    state: SIMD[DType.uint64, 2], rk: SIMD[DType.uint64, 2]
) -> SIMD[DType.uint64, 2]:
    return llvm_intrinsic["llvm.x86.aesni.aesenc", SIMD[DType.uint64, 2]](
        state, rk
    )


# AESENCLAST: ShiftRows + SubBytes + AddRoundKey(rk), no MixColumns.
@always_inline
def _aesenclast(
    state: SIMD[DType.uint64, 2], rk: SIMD[DType.uint64, 2]
) -> SIMD[DType.uint64, 2]:
    return llvm_intrinsic["llvm.x86.aesni.aesenclast", SIMD[DType.uint64, 2]](
        state, rk
    )


# AESDEC: InvShiftRows + InvSubBytes + InvMixColumns + AddRoundKey(rk).
@always_inline
def _aesdec(
    state: SIMD[DType.uint64, 2], rk: SIMD[DType.uint64, 2]
) -> SIMD[DType.uint64, 2]:
    return llvm_intrinsic["llvm.x86.aesni.aesdec", SIMD[DType.uint64, 2]](
        state, rk
    )


# AESDECLAST: InvShiftRows + InvSubBytes + AddRoundKey(rk), no InvMixColumns.
@always_inline
def _aesdeclast(
    state: SIMD[DType.uint64, 2], rk: SIMD[DType.uint64, 2]
) -> SIMD[DType.uint64, 2]:
    return llvm_intrinsic["llvm.x86.aesni.aesdeclast", SIMD[DType.uint64, 2]](
        state, rk
    )


# AESIMC: InvMixColumns — used to build the equivalent-inverse key schedule.
@always_inline
def _inv_mix(v: SIMD[DType.uint64, 2]) -> SIMD[DType.uint64, 2]:
    return llvm_intrinsic["llvm.x86.aesni.aesimc", SIMD[DType.uint64, 2]](v)


# FIPS 197 §5.1 Cipher() via AES-NI.
# Unlike ARM AESE (which XORs the key before SubBytes), AESENC folds
# AddRoundKey at the end — so rks[0] is applied with an explicit XOR and
# rks[Nr] is consumed by AESENCLAST.
def cipher[
    Nr: Int, o: MutOrigin
](data: Span[UInt8, o], rks: InlineArray[SIMD[DType.uint64, 2], Nr + 1]):
    var s = data.unsafe_ptr().bitcast[UInt64]().load[width=2]()
    s ^= rks[0]
    comptime for r in range(1, Nr):
        s = _aesenc(s, rks[r])
    s = _aesenclast(s, rks[Nr])
    data.unsafe_ptr().bitcast[UInt64]().store(s)


# FIPS 197 §5.3 InvCipher() via AES-NI (equivalent inverse).
# Key schedule: rks[0]=enc_rks[Nr], rks[1..Nr-1]=InvMixColumns(enc_rks[Nr-r]),
# rks[Nr]=enc_rks[0] — produced by _dec_from_enc_rks in setup.mojo.
def decipher[
    Nr: Int, o: MutOrigin
](data: Span[UInt8, o], rks: InlineArray[SIMD[DType.uint64, 2], Nr + 1]):
    var s = data.unsafe_ptr().bitcast[UInt64]().load[width=2]()
    s ^= rks[0]
    comptime for r in range(1, Nr):
        s = _aesdec(s, rks[r])
    s = _aesdeclast(s, rks[Nr])
    data.unsafe_ptr().bitcast[UInt64]().store(s)
