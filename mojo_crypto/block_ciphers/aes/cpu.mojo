from mojo_crypto.block_ciphers.errors import BlockSizeError
from .common import Nb, BLOCK_SIZE, SBOX, SBOX_INV


struct AesCpuBackend[KeySize: Int](ImplicitlyDestructible, Movable):
    comptime Nk: Int = Self.KeySize // 4
    comptime Nr: Int = Self.Nk + 6
    comptime WordsSize: Int = Nb * (Self.Nr + 1)

    var w: InlineArray[UInt32, Self.WordsSize]

    def __init__(out self, key: InlineArray[UInt8, Self.KeySize]):
        self.w = _key_expansion[WordsSize=Self.WordsSize, Nk=Self.Nk](key)

    def encrypt[Nr: Int, o: MutOrigin](self, data: Span[UInt8, o]) raises:
        BlockSizeError[BLOCK_SIZE].check(len(data))
        for i in range(len(data) // BLOCK_SIZE):
            var offset = i * BLOCK_SIZE
            cipher[Nr=Nr](data[offset : offset + BLOCK_SIZE], self.w)

    def decrypt[Nr: Int, o: MutOrigin](self, data: Span[UInt8, o]) raises:
        BlockSizeError[BLOCK_SIZE].check(len(data))
        for i in range(len(data) // BLOCK_SIZE):
            var offset = i * BLOCK_SIZE
            decipher[Nr=Nr](data[offset : offset + BLOCK_SIZE], self.w)


# FIPS 197 §5.1 Cipher()
# FIPS 197 §3.4: state[r][c] = in[r + 4*c] (column-major).
# All helpers operate directly on the flat InlineArray[UInt8, 16] using
# that index mapping: state[r][c] ↔ state[r + 4*c].
def cipher[
    Nr: Int, WordsSize: Int, o: MutOrigin
](state: Span[UInt8, o], w: InlineArray[UInt32, WordsSize]):
    add_round_key(state, 0, w)
    for r in range(1, Nr):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, r, w)
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, Nr, w)


# FIPS 197 §5.3 InvCipher()
def decipher[
    Nr: Int, WordsSize: Int, o: MutOrigin
](state: Span[UInt8, o], w: InlineArray[UInt32, WordsSize]):
    add_round_key(state, Nr, w)
    for r in range(Nr - 1, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, r, w)
        inv_mix_columns(state)
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, 0, w)


# FIPS 197 §5.1.4 AddRoundKey()
def add_round_key[
    WordsSize: Int, o: MutOrigin
](state: Span[UInt8, o], round: Int, w: InlineArray[UInt32, WordsSize],):
    for c in range(Nb):
        var w_idx = Nb * round + c
        state[4 * c] ^= UInt8(w[w_idx] >> 24)
        state[1 + 4 * c] ^= UInt8(w[w_idx] >> 16)
        state[2 + 4 * c] ^= UInt8(w[w_idx] >> 8)
        state[3 + 4 * c] ^= UInt8(w[w_idx])


# FIPS 197 §5.1.1 SubBytes() — apply S-box to every byte of the state
def sub_bytes[o: MutOrigin](state: Span[UInt8, o]):
    for i in range(16):
        state[i] = UInt8(SBOX[Int(state[i])])


# FIPS 197 §5.3.2 InvSubBytes() — apply inverse S-box to every byte
def inv_sub_bytes[o: MutOrigin](state: Span[UInt8, o]):
    for i in range(16):
        state[i] = SBOX_INV[Int(state[i])]


# FIPS 197 §5.1.2 ShiftRows() — cyclic left shift of row r by r positions
# Row r in flat layout occupies indices r, r+4, r+8, r+12
def shift_rows[o: MutOrigin](state: Span[UInt8, o]):
    for r in range(1, Nb):
        var tmp = InlineArray[UInt8, Nb](uninitialized=True)
        for c in range(Nb):
            tmp[c] = state[r + 4 * c]
        for c in range(Nb):
            state[r + 4 * c] = tmp[(c + r) % Nb]


# FIPS 197 §5.3.1 InvShiftRows() — cyclic right shift of row r by r positions
def inv_shift_rows[o: MutOrigin](state: Span[UInt8, o]):
    for r in range(1, Nb):
        var tmp = InlineArray[UInt8, Nb](uninitialized=True)
        for c in range(Nb):
            tmp[c] = state[r + 4 * c]
        for c in range(Nb):
            state[r + 4 * c] = tmp[(c - r + Nb) % Nb]


# FIPS 197 §5.1.3 MixColumns() — GF(2^8) matrix multiply on each column
# Column col in flat layout occupies indices 4*col, 1+4*col, 2+4*col, 3+4*col
def mix_columns[o: MutOrigin](state: Span[UInt8, o]):
    for col in range(Nb):
        var s0 = state[4 * col]
        var s1 = state[1 + 4 * col]
        var s2 = state[2 + 4 * col]
        var s3 = state[3 + 4 * col]
        state[4 * col] = multiply(0x02, s0) ^ multiply(0x03, s1) ^ s2 ^ s3
        state[1 + 4 * col] = s0 ^ multiply(0x02, s1) ^ multiply(0x03, s2) ^ s3
        state[2 + 4 * col] = s0 ^ s1 ^ multiply(0x02, s2) ^ multiply(0x03, s3)
        state[3 + 4 * col] = multiply(0x03, s0) ^ s1 ^ s2 ^ multiply(0x02, s3)


# FIPS 197 §5.3.3 InvMixColumns() — GF(2^8) inverse matrix multiply on each column
def inv_mix_columns[o: MutOrigin](state: Span[UInt8, o]):
    for col in range(Nb):
        var s0 = state[4 * col]
        var s1 = state[1 + 4 * col]
        var s2 = state[2 + 4 * col]
        var s3 = state[3 + 4 * col]
        state[4 * col] = (
            multiply(0x0E, s0)
            ^ multiply(0x0B, s1)
            ^ multiply(0x0D, s2)
            ^ multiply(0x09, s3)
        )
        state[1 + 4 * col] = (
            multiply(0x09, s0)
            ^ multiply(0x0E, s1)
            ^ multiply(0x0B, s2)
            ^ multiply(0x0D, s3)
        )
        state[2 + 4 * col] = (
            multiply(0x0D, s0)
            ^ multiply(0x09, s1)
            ^ multiply(0x0E, s2)
            ^ multiply(0x0B, s3)
        )
        state[3 + 4 * col] = (
            multiply(0x0B, s0)
            ^ multiply(0x0D, s1)
            ^ multiply(0x09, s2)
            ^ multiply(0x0E, s3)
        )


# General GF(2^8) multiply via Russian peasant: iterate over bits of `a`
@always_inline
def multiply(a: UInt8, b: UInt8) -> UInt8:
    var result: UInt8 = 0
    var factor = b
    var scalar = a
    while scalar != 0:
        if scalar & 1:
            result ^= factor
        factor = xtime(factor)
        scalar >>= 1
    return result


# Multiply by 0x02 in GF(2^8) with AES reduction polynomial x^8+x^4+x^3+x+1
@always_inline
def xtime(a: UInt8) -> UInt8:
    var result = a << 1
    if a & 0x80:
        result ^= 0x1B
    return result


# FIPS 197 Table 2 — round constants Rcon[1..10], stored 0-indexed.
comptime RCON: InlineArray[UInt32, 10] = [
    # fmt: off
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
    0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000,
    # fmt: on
]


# FIPS 197 §5.2 KeyExpansion()
# <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf>
def _key_expansion[
    WordsSize: Int, Nk: Int, KeySize: Int
](key: InlineArray[UInt8, KeySize]) -> InlineArray[UInt32, WordsSize]:
    var w = InlineArray[UInt32, WordsSize](uninitialized=True)
    for i in range(Nk):
        w[i] = (
            UInt32(key[4 * i]) << 24
            | UInt32(key[4 * i + 1]) << 16
            | UInt32(key[4 * i + 2]) << 8
            | UInt32(key[4 * i + 3])
        )
    for i in range(Nk, WordsSize):
        var temp = w[i - 1]
        if i % Nk == 0:
            temp = _sub_word(_rot_word(temp)) ^ RCON[i / Nk - 1]
        elif Nk > 6 and i % Nk == 4:
            temp = _sub_word(temp)
        w[i] = w[i - Nk] ^ temp
    return w


@always_inline
def _rot_word(w: UInt32) -> UInt32:
    # Cyclic left rotation by one byte: [a0,a1,a2,a3] → [a1,a2,a3,a0].
    return (w << 8) | (w >> 24)


@always_inline
def _sub_word(w: UInt32) -> UInt32:
    a0 = SBOX[w >> 24] << 24
    a1 = SBOX[w >> 16 & 0xFF] << 16
    a2 = SBOX[w >> 8 & 0xFF] << 8
    a3 = SBOX[w & 0xFF]
    return a0 | a1 | a2 | a3
