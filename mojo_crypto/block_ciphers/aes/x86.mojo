# LLVM X86 AES-NI intrinsics.
#
# LLVM x86 intrinsic definitions (.td is authoritative):
#   https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/IR/IntrinsicsX86.td
# Intel AES-NI reference:
#   https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html#text=aes

from std.sys.intrinsics import llvm_intrinsic

from mojo_crypto.block_ciphers.errors import BlockSizeError
from mojo_crypto.block_ciphers.traits import (
    BlockCipherEncryptable,
    BlockCipherDecryptable,
)
from ._common import BLOCK_SIZE, SBOX, _check_key_size


# All AES-NI instructions use v2i64 in LLVM IR. Round keys are stored as
# SIMD[DType.uint64, 2] so no conversion is needed at call sites; the state
# is bitcast once at load and once at store.
struct AesX86[KEY_SIZE: Int](
    BlockCipherDecryptable,
    BlockCipherEncryptable,
    Copyable,
    ImplicitlyDestructible,
    Movable,
):
    comptime BLOCK_SIZE: Int = BLOCK_SIZE
    comptime NK: Int = Self.KEY_SIZE // 4
    comptime NR: Int = Self.NK + 6

    var enc_rks: InlineArray[SIMD[DType.uint64, 2], Self.NR + 1]
    var dec_rks: InlineArray[SIMD[DType.uint64, 2], Self.NR + 1]

    def __init__(out self, key: InlineArray[UInt8, Self.KEY_SIZE]):
        _check_key_size[Self.KEY_SIZE]()

        self.enc_rks = _expand_enc_rks[Self.NR, Self.NK](key)
        self.dec_rks = _dec_from_enc_rks[Self.NR](self.enc_rks)

    def encrypt[o: MutOrigin](self, data: Span[UInt8, o]) raises:
        BlockSizeError[BLOCK_SIZE].check(len(data))
        for i in range(len(data) // BLOCK_SIZE):
            var offset = i * BLOCK_SIZE
            _cipher(data[offset : offset + BLOCK_SIZE], self.enc_rks)

    def decrypt[o: MutOrigin](self, data: Span[UInt8, o]) raises:
        BlockSizeError[BLOCK_SIZE].check(len(data))
        for i in range(len(data) // BLOCK_SIZE):
            var offset = i * BLOCK_SIZE
            _decipher(data[offset : offset + BLOCK_SIZE], self.dec_rks)


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
# rks[NR] is consumed by AESENCLAST.
def _cipher[
    NR: Int, o: MutOrigin
](data: Span[UInt8, o], rks: InlineArray[SIMD[DType.uint64, 2], NR + 1]):
    var s = data.unsafe_ptr().bitcast[UInt64]().load[width=2]()
    s ^= rks[0]
    comptime for r in range(1, NR):
        s = _aesenc(s, rks[r])
    s = _aesenclast(s, rks[NR])
    data.unsafe_ptr().bitcast[UInt64]().store(s)


# FIPS 197 §5.3 InvCipher() via AES-NI (equivalent inverse).
# Key schedule: rks[0]=enc_rks[NR], rks[1..NR-1]=InvMixColumns(enc_rks[NR-r]),
# rks[NR]=enc_rks[0] — produced by _dec_from_enc_rks in setup.mojo.
def _decipher[
    NR: Int, o: MutOrigin
](data: Span[UInt8, o], rks: InlineArray[SIMD[DType.uint64, 2], NR + 1]):
    var s = data.unsafe_ptr().bitcast[UInt64]().load[width=2]()
    s ^= rks[0]
    comptime for r in range(1, NR):
        s = _aesdec(s, rks[r])
    s = _aesdeclast(s, rks[NR])
    data.unsafe_ptr().bitcast[UInt64]().store(s)


# FIPS 197 Table 2 — round constants Rcon[1..10], stored 0-indexed.
comptime RCON: InlineArray[UInt8, 10] = [
    # fmt: off
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    # fmt: on
]


# Build NR+1 encrypt round keys directly from the raw key bytes.
# Maintains a flat byte buffer kb[] where kb[wi*4 .. wi*4+3] = word wi.
# The column-major layout (rk[4*c+b] = col c, byte b) matches the byte
# order in kb[] directly, so each round key is a plain 16-byte load.
def _expand_enc_rks[
    NR: Int, NK: Int, KEY_SIZE: Int
](key: InlineArray[UInt8, KEY_SIZE]) -> InlineArray[
    SIMD[DType.uint64, 2], NR + 1
]:
    var kb = InlineArray[UInt8, (NR + 1) * 16](uninitialized=True)
    for i in range(KEY_SIZE):
        kb[i] = key[i]
    for wi in range(NK, (NR + 1) * 4):
        var b0 = kb[(wi - 1) * 4]
        var b1 = kb[(wi - 1) * 4 + 1]
        var b2 = kb[(wi - 1) * 4 + 2]
        var b3 = kb[(wi - 1) * 4 + 3]
        if wi % NK == 0:
            # RotWord: [b0,b1,b2,b3] → [b1,b2,b3,b0]; SubWord; XOR Rcon (MSB only).
            var t = UInt8(SBOX[b0])
            b0 = UInt8(SBOX[b1]) ^ RCON[wi // NK - 1]
            b1 = UInt8(SBOX[b2])
            b2 = UInt8(SBOX[b3])
            b3 = t
        comptime if NK > 6:
            if wi % NK == 4:
                b0 = UInt8(SBOX[b0])
                b1 = UInt8(SBOX[b1])
                b2 = UInt8(SBOX[b2])
                b3 = UInt8(SBOX[b3])
        kb[wi * 4] = kb[(wi - NK) * 4] ^ b0
        kb[wi * 4 + 1] = kb[(wi - NK) * 4 + 1] ^ b1
        kb[wi * 4 + 2] = kb[(wi - NK) * 4 + 2] ^ b2
        kb[wi * 4 + 3] = kb[(wi - NK) * 4 + 3] ^ b3
    var rks = InlineArray[SIMD[DType.uint64, 2], NR + 1](uninitialized=True)
    for r in range(NR + 1):
        rks[r] = (kb.unsafe_ptr() + r * 16).bitcast[UInt64]().load[width=2]()
    return rks


# Convert encrypt round keys to the equivalent-inverse schedule for _decipher().
# dk[0]=ek[NR], dk[1..NR-1]=aesimc(ek[NR-r]), dk[NR]=ek[0].
def _dec_from_enc_rks[
    NR: Int
](enc_rks: InlineArray[SIMD[DType.uint64, 2], NR + 1]) -> InlineArray[
    SIMD[DType.uint64, 2], NR + 1
]:
    var rks = InlineArray[SIMD[DType.uint64, 2], NR + 1](uninitialized=True)
    rks[0] = enc_rks[NR]
    comptime for r in range(1, NR):
        rks[r] = _inv_mix(enc_rks[NR - r])
    rks[NR] = enc_rks[0]
    return rks
