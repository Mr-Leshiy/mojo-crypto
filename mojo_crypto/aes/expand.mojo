from .common import SBOX, Nb

# FIPS 197 Table 2 — round constants, 0-indexed (Rcon[1]..Rcon[10])
comptime RCON: InlineArray[UInt32, 10] = [
    # fmt: off
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
    0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000,
    # fmt: on
]


# FIPS 197 Algorithm 2 — KEYEXPANSION, AES-128 only
# key: 16 bytes (128 bits), output: 44 words (11 round keys)
# <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf>
# 5.2 KeyExpansion()
def key_expansion[
    WordsSize: Int, Nk: Int, KeySize: Int
](key: InlineArray[UInt8, KeySize]) -> InlineArray[UInt32, WordsSize]:
    var w = InlineArray[UInt32, WordsSize](uninitialized=True)

    for i in range(Nk):
        var word: UInt32 = (
            UInt32(key[4 * i]) << 24
            | UInt32(key[4 * i + 1]) << 16
            | UInt32(key[4 * i + 2]) << 8
            | UInt32(key[4 * i + 3])
        )
        w[i] = word

    for i in range(Nk, WordsSize):
        var temp: UInt32 = w[i - 1]
        if i % Nk == 0:
            temp = sub_word(rot_word(temp)) ^ RCON[i / Nk - 1]
        elif Nk > 6 and i % Nk == 4:
            temp = sub_word(temp)
        w[i] = w[i - Nk] ^ temp
    return w


@always_inline
def rot_word(w: UInt32) -> UInt32:
    # Cyclic left rotation by one byte: [a0, a1, a2, a3] → [a1, a2, a3, a0].
    # No overflow: UInt32 shifts discard bits that fall off the edge and fill
    # with zeros from the other side.
    #   w << 8  → [a1, a2, a3, 00]  (a0 discarded from the top)
    #   w >> 24 → [00, 00, 00, a0]  (a0 recovered at the bottom)
    #   OR      → [a1, a2, a3, a0]
    return (w << 8) | (w >> 24)


@always_inline
def sub_word(w: UInt32) -> UInt32:
    a0 = SBOX[w >> 24] << 24
    a1 = SBOX[w >> 16 & 0xFF] << 16
    a2 = SBOX[w >> 8 & 0xFF] << 8
    a3 = SBOX[w & 0xFF]
    return a0 | a1 | a2 | a3
