from ..common import Nb, SBOX, SBOX_INV

# FIPS 197 §3.4: state[r][c] = in[r + 4*c] (column-major).
# All helpers operate directly on the flat InlineArray[UInt8, 16] using
# that index mapping: state[r][c] ↔ state[r + 4*c].


def cipher[Nr: Int, WordsSize: Int](
    input: InlineArray[UInt8, 16], w: InlineArray[UInt32, WordsSize]
) -> InlineArray[UInt8, 16]:
    var state = input
    add_round_key(state, 0, w)
    for r in range(1, Nr):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, r, w)
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, Nr, w)
    return state


# FIPS 197 §5.3 InvCipher()
def decipher[Nr: Int, WordsSize: Int](
    input: InlineArray[UInt8, 16], w: InlineArray[UInt32, WordsSize]
) -> InlineArray[UInt8, 16]:
    var state = input
    add_round_key(state, Nr, w)
    for i in range(Nr - 1):
        var round = Nr - 1 - i
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round, w)
        inv_mix_columns(state)
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, 0, w)
    return state


# FIPS 197 §5.1.4 AddRoundKey()
def add_round_key[WordsSize: Int](
    mut state: InlineArray[UInt8, 16], round: Int, w: InlineArray[UInt32, WordsSize]
):
    for c in range(Nb):
        var w_idx = Nb * round + c
        state[4 * c] ^= UInt8(w[w_idx] >> 24)
        state[1 + 4 * c] ^= UInt8(w[w_idx] >> 16)
        state[2 + 4 * c] ^= UInt8(w[w_idx] >> 8)
        state[3 + 4 * c] ^= UInt8(w[w_idx])


# FIPS 197 §5.1.1 SubBytes() — apply S-box to every byte of the state
def sub_bytes(mut state: InlineArray[UInt8, 16]):
    for i in range(16):
        state[i] = UInt8(SBOX[Int(state[i])])


# FIPS 197 §5.3.2 InvSubBytes() — apply inverse S-box to every byte
def inv_sub_bytes(mut state: InlineArray[UInt8, 16]):
    for i in range(16):
        state[i] = SBOX_INV[Int(state[i])]


# FIPS 197 §5.1.2 ShiftRows() — cyclic left shift of row r by r positions
# Row r in flat layout occupies indices r, r+4, r+8, r+12
def shift_rows(mut state: InlineArray[UInt8, 16]):
    for r in range(1, Nb):
        var tmp = InlineArray[UInt8, Nb](uninitialized=True)
        for c in range(Nb):
            tmp[c] = state[r + 4 * c]
        for c in range(Nb):
            state[r + 4 * c] = tmp[(c + r) % Nb]


# FIPS 197 §5.3.1 InvShiftRows() — cyclic right shift of row r by r positions
def inv_shift_rows(mut state: InlineArray[UInt8, 16]):
    for r in range(1, Nb):
        var tmp = InlineArray[UInt8, Nb](uninitialized=True)
        for c in range(Nb):
            tmp[c] = state[r + 4 * c]
        for c in range(Nb):
            state[r + 4 * c] = tmp[(c - r + Nb) % Nb]


# FIPS 197 §5.1.3 MixColumns() — GF(2^8) matrix multiply on each column
# Column col in flat layout occupies indices 4*col, 1+4*col, 2+4*col, 3+4*col
def mix_columns(mut state: InlineArray[UInt8, 16]):
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
def inv_mix_columns(mut state: InlineArray[UInt8, 16]):
    for col in range(Nb):
        var s0 = state[4 * col]
        var s1 = state[1 + 4 * col]
        var s2 = state[2 + 4 * col]
        var s3 = state[3 + 4 * col]
        state[4 * col] = (
            multiply(0x0E, s0) ^ multiply(0x0B, s1) ^ multiply(0x0D, s2) ^ multiply(0x09, s3)
        )
        state[1 + 4 * col] = (
            multiply(0x09, s0) ^ multiply(0x0E, s1) ^ multiply(0x0B, s2) ^ multiply(0x0D, s3)
        )
        state[2 + 4 * col] = (
            multiply(0x0D, s0) ^ multiply(0x09, s1) ^ multiply(0x0E, s2) ^ multiply(0x0B, s3)
        )
        state[3 + 4 * col] = (
            multiply(0x0B, s0) ^ multiply(0x0D, s1) ^ multiply(0x09, s2) ^ multiply(0x0E, s3)
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
