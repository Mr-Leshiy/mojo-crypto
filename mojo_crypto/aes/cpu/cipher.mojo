from ..common import Nb, SBOX, SBOX_INV, MUL2, MUL3, MUL9, MUL11, MUL13, MUL14


# FIPS 197 §5.1 Cipher()
# FIPS 197 §3.4: state[r][c] = in[r + 4*c] (column-major).
# All helpers operate directly on the flat InlineArray[UInt8, 16] using
# that index mapping: state[r][c] ↔ state[r + 4*c].
def cipher[
    Nr: Int, WordsSize: Int
](mut state: InlineArray[UInt8, 16], w: InlineArray[UInt32, WordsSize]):
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
    Nr: Int, WordsSize: Int
](mut state: InlineArray[UInt8, 16], w: InlineArray[UInt32, WordsSize]):
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
    WordsSize: Int
](
    mut state: InlineArray[UInt8, 16],
    round: Int,
    w: InlineArray[UInt32, WordsSize],
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
        state[4 * col] = MUL2[Int(s0)] ^ MUL3[Int(s1)] ^ s2 ^ s3
        state[1 + 4 * col] = s0 ^ MUL2[Int(s1)] ^ MUL3[Int(s2)] ^ s3
        state[2 + 4 * col] = s0 ^ s1 ^ MUL2[Int(s2)] ^ MUL3[Int(s3)]
        state[3 + 4 * col] = MUL3[Int(s0)] ^ s1 ^ s2 ^ MUL2[Int(s3)]


# FIPS 197 §5.3.3 InvMixColumns() — GF(2^8) inverse matrix multiply on each column
def inv_mix_columns(mut state: InlineArray[UInt8, 16]):
    for col in range(Nb):
        var s0 = state[4 * col]
        var s1 = state[1 + 4 * col]
        var s2 = state[2 + 4 * col]
        var s3 = state[3 + 4 * col]
        state[4 * col] = (
            MUL14[Int(s0)] ^ MUL11[Int(s1)] ^ MUL13[Int(s2)] ^ MUL9[Int(s3)]
        )
        state[1 + 4 * col] = (
            MUL9[Int(s0)] ^ MUL14[Int(s1)] ^ MUL11[Int(s2)] ^ MUL13[Int(s3)]
        )
        state[2 + 4 * col] = (
            MUL13[Int(s0)] ^ MUL9[Int(s1)] ^ MUL14[Int(s2)] ^ MUL11[Int(s3)]
        )
        state[3 + 4 * col] = (
            MUL11[Int(s0)] ^ MUL13[Int(s1)] ^ MUL9[Int(s2)] ^ MUL14[Int(s3)]
        )
