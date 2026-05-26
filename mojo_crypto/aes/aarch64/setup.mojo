from ..common import SBOX
from .cipher import _inv_mix


# FIPS 197 Table 2 — round constants Rcon[1..10], stored 0-indexed.
comptime RCON: InlineArray[UInt8, 10] = [
    # fmt: off
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    # fmt: on
]


struct AesArmv8Backend[KeySize: Int](ImplicitlyDestructible, Movable):
    comptime Nk: Int = Self.KeySize // 4
    comptime Nr: Int = Self.Nk + 6

    var enc_rks: InlineArray[SIMD[DType.uint8, 16], Self.Nr + 1]
    var dec_rks: InlineArray[SIMD[DType.uint8, 16], Self.Nr + 1]

    def __init__(out self, key: InlineArray[UInt8, Self.KeySize]):
        self.enc_rks = _expand_enc_rks[Self.Nr, Self.Nk](key)
        self.dec_rks = _dec_from_enc_rks[Self.Nr](self.enc_rks)


# Build Nr+1 encrypt round keys directly from the raw key bytes.
# Maintains a flat byte buffer kb[] where kb[wi*4 .. wi*4+3] = word wi.
# The column-major layout (rk[4*c+b] = col c, byte b) matches the byte
# order in kb[] directly, so each round key is a plain 16-byte load.
def _expand_enc_rks[
    Nr: Int, Nk: Int, KeySize: Int
](key: InlineArray[UInt8, KeySize]) -> InlineArray[
    SIMD[DType.uint8, 16], Nr + 1
]:
    var kb = InlineArray[UInt8, (Nr + 1) * 16](uninitialized=True)
    for i in range(KeySize):
        kb[i] = key[i]
    for wi in range(Nk, (Nr + 1) * 4):
        var b0 = kb[(wi - 1) * 4]
        var b1 = kb[(wi - 1) * 4 + 1]
        var b2 = kb[(wi - 1) * 4 + 2]
        var b3 = kb[(wi - 1) * 4 + 3]
        if wi % Nk == 0:
            # RotWord: [b0,b1,b2,b3] → [b1,b2,b3,b0]; SubWord; XOR Rcon (MSB only).
            var t = UInt8(SBOX[b0])
            b0 = UInt8(SBOX[b1]) ^ RCON[wi // Nk - 1]
            b1 = UInt8(SBOX[b2])
            b2 = UInt8(SBOX[b3])
            b3 = t
        comptime if Nk > 6:
            if wi % Nk == 4:
                b0 = UInt8(SBOX[b0])
                b1 = UInt8(SBOX[b1])
                b2 = UInt8(SBOX[b2])
                b3 = UInt8(SBOX[b3])
        kb[wi * 4] = kb[(wi - Nk) * 4] ^ b0
        kb[wi * 4 + 1] = kb[(wi - Nk) * 4 + 1] ^ b1
        kb[wi * 4 + 2] = kb[(wi - Nk) * 4 + 2] ^ b2
        kb[wi * 4 + 3] = kb[(wi - Nk) * 4 + 3] ^ b3
    var rks = InlineArray[SIMD[DType.uint8, 16], Nr + 1](uninitialized=True)
    for r in range(Nr + 1):
        rks[r] = (kb.unsafe_ptr() + r * 16).load[width=16]()
    return rks


# Convert encrypt round keys to the equivalent-inverse schedule for decipher().
# Mirrors expand_round_keys_inv() from cipher.mojo, operating on SIMD keys
# instead of UInt32 words: dk[0]=ek[Nr], dk[1..Nr-1]=aesimc(ek[Nr-r]), dk[Nr]=ek[0].
def _dec_from_enc_rks[
    Nr: Int
](enc_rks: InlineArray[SIMD[DType.uint8, 16], Nr + 1]) -> InlineArray[
    SIMD[DType.uint8, 16], Nr + 1
]:
    var rks = InlineArray[SIMD[DType.uint8, 16], Nr + 1](uninitialized=True)
    rks[0] = enc_rks[Nr]
    comptime for r in range(1, Nr):
        rks[r] = _inv_mix(enc_rks[Nr - r])
    rks[Nr] = enc_rks[0]
    return rks
