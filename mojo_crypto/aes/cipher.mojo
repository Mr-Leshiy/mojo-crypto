from .common import Nb, SBOX
from .expand import key_expansion


def cipher[
    Nr: Int, Nk: Int, KeySize: Int
](input: InlineArray[UInt8, 16], key: InlineArray[UInt8, KeySize]) -> InlineArray[
    UInt8, 16
]:
    comptime WordsSize: Int = Nb * (Nr + 1)

    w = key_expansion[WordsSize, Nk, KeySize](key)
    var state = bytes_to_state(input)
    add_round_key(state, 0, w)
    for r in range(1, Nr):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, r, w)

    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, Nr, w)
    return state_to_bytes(state)


comptime StateData = InlineArray[InlineArray[UInt8, Nb], Nb]


# FIPS 197 §3.4: state[r][c] = in[r + 4*c]  (column-major input mapping)
def bytes_to_state(input: InlineArray[UInt8, 16]) -> StateData:
    var state = StateData(uninitialized=True)
    for r in range(Nb):
        for c in range(Nb):
            state[r][c] = input[r + Nb * c]
    return state


# FIPS 197 §3.4: out[r + 4*c] = state[r][c]
def state_to_bytes(state: StateData) -> InlineArray[UInt8, 16]:
    var output = InlineArray[UInt8, 16](uninitialized=True)
    for r in range(Nb):
        for c in range(Nb):
            output[r + Nb * c] = state[r][c]
    return output


# <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf>
# 5.1.4 AddRoundKey()
def add_round_key[
    WordsSize: Int
](mut state: StateData, round: Int, w: InlineArray[UInt32, WordsSize]):
    for c in range(Nb):
        w_idx = Nb * round + c
        state[0][c] ^= UInt8(w[w_idx] >> 24)
        state[1][c] ^= UInt8(w[w_idx] >> 16)
        state[2][c] ^= UInt8(w[w_idx] >> 8)
        state[3][c] ^= UInt8(w[w_idx])


# FIPS 197 §5.1.1 SubBytes() — apply S-box to every byte of the state
def sub_bytes(mut state: StateData):
    for r in range(Nb):
        for c in range(Nb):
            state[r][c] = UInt8(SBOX[Int(state[r][c])])


# FIPS 197 §5.1.2 ShiftRows() — cyclic left shift of row r by r positions
def shift_rows(mut state: StateData):
    for r in range(1, Nb):
        var row = InlineArray[UInt8, Nb](uninitialized=True)
        for c in range(Nb):
            row[c] = state[r][c]
        for c in range(Nb):
            state[r][c] = row[(c + r) % Nb]


# Multiply by 0x02 in GF(2^8) with AES reduction polynomial x^8+x^4+x^3+x+1
@always_inline
def xtime(a: UInt8) -> UInt8:
    var result = a << 1
    if a & 0x80:
        result ^= 0x1B
    return result


# FIPS 197 §5.1.3 MixColumns() — GF(2^8) matrix multiply on each column
def mix_columns(mut state: StateData):
    for col in range(Nb):
        var s0 = state[0][col]
        var s1 = state[1][col]
        var s2 = state[2][col]
        var s3 = state[3][col]
        state[0][col] = xtime(s0) ^ xtime(s1) ^ s1 ^ s2 ^ s3
        state[1][col] = s0 ^ xtime(s1) ^ xtime(s2) ^ s2 ^ s3
        state[2][col] = s0 ^ s1 ^ xtime(s2) ^ xtime(s3) ^ s3
        state[3][col] = xtime(s0) ^ s0 ^ s1 ^ s2 ^ xtime(s3)
