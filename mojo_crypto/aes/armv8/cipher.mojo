# ARMv8 Cryptography Extension — AES acceleration.
#
# Uses four LLVM intrinsics that map 1:1 to ARMv8-A AES instructions.
# LLVM AArch64 intrinsic definitions (no separate doc page exists; .td is authoritative):
#   https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/IR/IntrinsicsAArch64.td
# ARM intrinsics browser (filter by "AES", A64 SIMD):
#   https://developer.arm.com/architectures/instruction-sets/intrinsics/
# ARM Architecture Reference Manual (A-profile), section C7.2 (crypto instructions):
#   https://developer.arm.com/documentation/ddi0487/latest
#
# Intrinsic → ARM instruction → operation
#   llvm.aarch64.crypto.aese  → AESE  → AddRoundKey(state, key); SubBytes; ShiftRows
#   llvm.aarch64.crypto.aesmc → AESMC → MixColumns
#   llvm.aarch64.crypto.aesd  → AESD  → AddRoundKey(state, key); InvSubBytes; InvShiftRows
#   llvm.aarch64.crypto.aesimc→ AESIMC→ InvMixColumns
#
# All four operate on 128-bit vectors (SIMD[DType.uint8, 16]).
# Requires +aes CPU feature (implied by ARMv8-A and later; always present on
# Apple Silicon and Linux aarch64 server/desktop hardware).


from std.sys import CompilationTarget
from std.sys.intrinsics import llvm_intrinsic

from ..common import Nb, BLOCK_SIZE


# AESE: AddRoundKey(state XOR key), SubBytes, ShiftRows → next-round state.
# Note: AESE fuses AddRoundKey into the instruction — key is XOR'd before the
# S-box, not after. This produces the "lag-by-one" key schedule used in cipher().
@always_inline
def _aese(
    state: SIMD[DType.uint8, 16], key: SIMD[DType.uint8, 16]
) -> SIMD[DType.uint8, 16]:
    return llvm_intrinsic["llvm.aarch64.crypto.aese", SIMD[DType.uint8, 16]](
        state, key
    )


# AESMC: MixColumns on the output of AESE.
@always_inline
def _aesmc(state: SIMD[DType.uint8, 16]) -> SIMD[DType.uint8, 16]:
    return llvm_intrinsic["llvm.aarch64.crypto.aesmc", SIMD[DType.uint8, 16]](
        state
    )


# AESD: AddRoundKey(state XOR key), InvSubBytes, InvShiftRows → next-round state.
@always_inline
def _aesd(
    state: SIMD[DType.uint8, 16], key: SIMD[DType.uint8, 16]
) -> SIMD[DType.uint8, 16]:
    return llvm_intrinsic["llvm.aarch64.crypto.aesd", SIMD[DType.uint8, 16]](
        state, key
    )


# AESIMC: InvMixColumns — used to convert encrypt round keys to the
# equivalent-inverse schedule (see expand_round_keys_inv).
@always_inline
def _inv_mix(v: SIMD[DType.uint8, 16]) -> SIMD[DType.uint8, 16]:
    return llvm_intrinsic["llvm.aarch64.crypto.aesimc", SIMD[DType.uint8, 16]](
        v
    )


# Convert one round's key words w[round*4 .. round*4+3] into a SIMD[uint8, 16].
# State layout is column-major (FIPS 197 §3.4): bytes[4*c + r] = row r, col c.
# Each word w[round*4+c] encodes column c big-endian: byte0=w>>24 .. byte3=w&0xFF.
@always_inline
def _rk[WordsSize: Int](
    w: InlineArray[UInt32, WordsSize], round: Int
) -> SIMD[DType.uint8, 16]:
    var rk = SIMD[DType.uint8, 16](0)
    comptime for c in range(Nb):
        var word = w[round * Nb + c]
        rk[4 * c] = UInt8(word >> 24)
        rk[4 * c + 1] = UInt8(word >> 16)
        rk[4 * c + 2] = UInt8(word >> 8)
        rk[4 * c + 3] = UInt8(word)
    return rk


# Precompute all Nr+1 encrypt round keys as 128-bit SIMD registers.
# Called once before a multi-block encrypt loop; avoids recomputing _rk per block.
def expand_round_keys[
    Nr: Int, WordsSize: Int
](w: InlineArray[UInt32, WordsSize]) -> InlineArray[SIMD[DType.uint8, 16], Nr + 1]:
    var rks = InlineArray[SIMD[DType.uint8, 16], Nr + 1](uninitialized=True)
    comptime for r in range(Nr + 1):
        rks[r] = _rk(w, r)
    return rks


# Precompute the Nr+1 equivalent-inverse round keys needed by decipher().
# Called once before a multi-block decrypt loop.
#
# The equivalent-inverse cipher (FIPS 197 §5.3.5) reorders InvSubBytes /
# InvShiftRows so they commute with InvMixColumns, letting AESD+AESIMC be
# chained the same way AESE+AESMC are. The key schedule transform is:
#   dk[0]       = ek[Nr]              (first AESD input — no InvMixColumns)
#   dk[1..Nr-1] = aesimc(ek[Nr-1..1]) (middle rounds — pre-apply InvMixColumns)
#   dk[Nr]      = ek[0]              (final XOR — no InvMixColumns)
def expand_round_keys_inv[
    Nr: Int, WordsSize: Int
](w: InlineArray[UInt32, WordsSize]) -> InlineArray[SIMD[DType.uint8, 16], Nr + 1]:
    var rks = InlineArray[SIMD[DType.uint8, 16], Nr + 1](uninitialized=True)
    rks[0] = _rk(w, Nr)
    comptime for r in range(1, Nr):
        rks[r] = _inv_mix(_rk(w, Nr - r))
    rks[Nr] = _rk(w, 0)
    return rks


# FIPS 197 §5.1 Cipher() via ARMv8 Crypto Extension.
#
# "Lag-by-one" pattern: AESE(state, rk[r]) performs AddRoundKey(r) +
# SubBytes + ShiftRows together. MixColumns follows separately via AESMC.
# The final round skips MixColumns and XORs the last key directly.
#
#   for r in 0..Nr-2: state = aesmc(aese(state, rk[r]))
#   state = aese(state, rk[Nr-1])
#   state ^= rk[Nr]
#
# rks must come from expand_round_keys(). comptime for unrolls all rounds.
# data.unsafe_ptr().load/store emit a single 128-bit LDR/STR instruction.
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
#
# Mirrors the encrypt pattern using AESD+AESIMC. rks must come from
# expand_round_keys_inv() — the equivalent-inverse schedule is pre-applied
# there so the hot loop here is identical in structure to cipher().
#
#   state = aesd(state, dk[0]); state = aesimc(state)
#   for r in 1..Nr-2: state = aesd(state, dk[r]); state = aesimc(state)
#   state = aesd(state, dk[Nr-1])
#   state ^= dk[Nr]
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
