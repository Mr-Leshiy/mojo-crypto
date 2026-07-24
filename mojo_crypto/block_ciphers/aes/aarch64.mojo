# LLVM AArch64 crypto AES intrinsics.
#
# LLVM AArch64 intrinsic definitions (no separate doc page exists; .td is authoritative):
#   https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/IR/IntrinsicsAArch64.td

from std.sys.intrinsics import llvm_intrinsic

from mojo_crypto.block_ciphers.errors import BlockSizeError
from mojo_crypto.block_ciphers.traits import (
    BlockCipherEncryptable,
    BlockCipherDecryptable,
)
from ._common import BLOCK_SIZE, SBOX, _check_key_size


struct AesAarch64[KEY_SIZE: Int](
    BlockCipherDecryptable,
    BlockCipherEncryptable,
    Copyable,
    ImplicitlyDestructible,
    Movable,
):
    comptime BLOCK_SIZE: Int = BLOCK_SIZE
    comptime NK: Int = Self.KEY_SIZE // 4
    comptime NR: Int = Self.NK + 6

    var enc_rks: InlineArray[SIMD[DType.uint8, 16], Self.NR + 1]
    var dec_rks: InlineArray[SIMD[DType.uint8, 16], Self.NR + 1]

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


# AESE: AddRoundKey(state XOR key), SubBytes, ShiftRows → next-round state.
# Note: AESE fuses AddRoundKey into the instruction — key is XOR'd before the
# S-box, not after. This produces the "lag-by-one" key schedule used in _cipher().
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
def _cipher[
    NR: Int, o: MutOrigin
](data: Span[UInt8, o], rks: InlineArray[SIMD[DType.uint8, 16], NR + 1]):
    var s = data.unsafe_ptr().load[width=BLOCK_SIZE]()
    comptime for r in range(NR - 1):
        s = _aesmc(_aese(s, rks[r]))
    s = _aese(s, rks[NR - 1])
    s ^= rks[NR]
    data.unsafe_ptr().store(s)


# FIPS 197 §5.3 InvCipher() via ARMv8 Crypto Extension (equivalent inverse).
def _decipher[
    NR: Int, o: MutOrigin
](data: Span[UInt8, o], rks: InlineArray[SIMD[DType.uint8, 16], NR + 1]):
    var s = data.unsafe_ptr().load[width=BLOCK_SIZE]()
    s = _aesd(s, rks[0])
    s = _inv_mix(s)
    comptime for r in range(1, NR - 1):
        s = _aesd(s, rks[r])
        s = _inv_mix(s)
    s = _aesd(s, rks[NR - 1])
    s ^= rks[NR]
    data.unsafe_ptr().store(s)


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
    SIMD[DType.uint8, 16], NR + 1
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
    var rks = InlineArray[SIMD[DType.uint8, 16], NR + 1](uninitialized=True)
    for r in range(NR + 1):
        rks[r] = (kb.unsafe_ptr() + r * 16).load[width=16]()
    return rks


# Convert encrypt round keys to the equivalent-inverse schedule for _decipher().
# Mirrors expand_round_keys_inv() from naive.mojo, operating on SIMD keys
# instead of UInt32 words: dk[0]=ek[NR], dk[1..NR-1]=aesimc(ek[NR-r]), dk[NR]=ek[0].
def _dec_from_enc_rks[
    NR: Int
](enc_rks: InlineArray[SIMD[DType.uint8, 16], NR + 1]) -> InlineArray[
    SIMD[DType.uint8, 16], NR + 1
]:
    var rks = InlineArray[SIMD[DType.uint8, 16], NR + 1](uninitialized=True)
    rks[0] = enc_rks[NR]
    comptime for r in range(1, NR):
        rks[r] = _inv_mix(enc_rks[NR - r])
    rks[NR] = enc_rks[0]
    return rks
