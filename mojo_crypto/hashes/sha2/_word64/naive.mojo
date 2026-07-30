from std.memory import unsafe_memcpy
from std.math import min

from mojo_crypto.hashes.traits import Digest
from mojo_crypto.utils import load_be


struct _Sha2Naive64[
    H0: UInt64,
    H1: UInt64,
    H2: UInt64,
    H3: UInt64,
    H4: UInt64,
    H5: UInt64,
    H6: UInt64,
    H7: UInt64,
    DigestSize: Int,
](Copyable, Digest, ImplicitlyDeletable, Movable):
    """
    Naive **SHA-2 (64-bit word)** engine — FIPS 180-4 §6.4.

    Backs SHA-384, SHA-512, SHA-512/224, and SHA-512/256, which differ only
    in the initial hash value (`H0..H7`) and output truncation
    (`DigestSize`); the Merkle-Damgard structure, message schedule, and
    compression function are identical.
    """

    comptime BLOCK_SIZE: Int = 128
    comptime OUTPUT_SIZE: Int = Self.DigestSize

    var _state: SIMD[DType.uint64, 8]
    var _buffer: InlineArray[UInt8, Self.BLOCK_SIZE]
    var _buffer_len: Int
    var _total_len: UInt64

    def __init__(out self):
        self._state = Self._iv()
        self._buffer = InlineArray[UInt8, Self.BLOCK_SIZE](uninitialized=True)
        self._buffer_len = 0
        self._total_len = 0

    @staticmethod
    def _iv() -> SIMD[DType.uint64, 8]:
        return SIMD[DType.uint64, 8](
            Self.H0,
            Self.H1,
            Self.H2,
            Self.H3,
            Self.H4,
            Self.H5,
            Self.H6,
            Self.H7,
        )

    def update[o: Origin](mut self, data: Span[UInt8, o]):
        """Absorb more input."""
        var input = data
        self._total_len += UInt64(len(input))

        # A prior `update` call left a partial block buffered — top it off
        # before deciding whether it is now full.
        if self._buffer_len > 0:
            var take = min(Self.BLOCK_SIZE - self._buffer_len, len(input))
            unsafe_memcpy(
                dest=UnsafePointer(self._buffer.unsafe_ptr())
                + self._buffer_len,
                src=input.unsafe_ptr(),
                count=take,
            )
            self._buffer_len += take
            input = input[take:]
            if self._buffer_len == Self.BLOCK_SIZE:
                _compress(self._state, self._buffer)
                self._buffer_len = 0

        while len(input) >= Self.BLOCK_SIZE:
            var block = InlineArray[UInt8, Self.BLOCK_SIZE](uninitialized=True)
            unsafe_memcpy(
                dest=block.unsafe_ptr(),
                src=input.unsafe_ptr(),
                count=Self.BLOCK_SIZE,
            )
            _compress(self._state, block)
            input = input[Self.BLOCK_SIZE :]

        if len(input) > 0:
            unsafe_memcpy(
                dest=UnsafePointer(self._buffer.unsafe_ptr())
                + self._buffer_len,
                src=input.unsafe_ptr(),
                count=len(input),
            )
            self._buffer_len += len(input)

    def finalize(var self) -> InlineArray[UInt8, Self.OUTPUT_SIZE]:
        """Consume self and return the OUTPUT_SIZE-byte digest."""

        # FIPS 180-4 §5.1.2: append 0x80, zero-pad to 112 mod 128, then the
        # message's bit length as a 128-bit big-endian integer. Messages this
        # implementation can hold are always far short of 2^64 bytes, so the
        # upper 8 bytes of that 128-bit field are always zero.
        var bit_len = self._total_len * 8

        self._buffer[self._buffer_len] = 0x80
        var pad_len = self._buffer_len + 1

        if pad_len > Self.BLOCK_SIZE - 16:
            for i in range(pad_len, Self.BLOCK_SIZE):
                self._buffer[i] = 0
            _compress(self._state, self._buffer)
            pad_len = 0

        for i in range(pad_len, Self.BLOCK_SIZE - 16):
            self._buffer[i] = 0
        for i in range(8):
            self._buffer[Self.BLOCK_SIZE - 16 + i] = 0
        for i in range(8):
            self._buffer[Self.BLOCK_SIZE - 8 + i] = UInt8(
                bit_len >> UInt64(8 * (7 - i))
            )
        _compress(self._state, self._buffer)

        var out = InlineArray[UInt8, Self.OUTPUT_SIZE](uninitialized=True)
        for i in range(Self.OUTPUT_SIZE):
            out[i] = UInt8(self._state[i // 8] >> UInt64(8 * (7 - i % 8)))
        return out^

    def reset(mut self):
        """Reset the hash to its initial state."""
        self._state = Self._iv()
        self._buffer_len = 0
        self._total_len = 0


# FIPS 180-4 §6.2.2 — number of rounds in the 32-bit-word compression
# function (SHA-224/256), and thus the size of the expanded message schedule
# and the K32 table below.
comptime ROUNDS_32: Int = 64

# FIPS 180-4 §6.4.2 — number of rounds in the 64-bit-word compression
# function (SHA-384/512/512-224/512-256), and thus the size of the expanded
# message schedule and the K64 table below.
comptime ROUNDS_64: Int = 80

# FIPS 180-4 §4.2.2 — round constants for the 32-bit word engine (SHA-224/256).
comptime K32: InlineArray[UInt32, ROUNDS_32] = [
    # fmt: off
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    # fmt: on
]

# FIPS 180-4 §4.2.3 — round constants for the 64-bit word engine (SHA-384/512/512-224/512-256).
comptime K64: InlineArray[UInt64, ROUNDS_64] = [
    # fmt: off
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
    # fmt: on
]

# FIPS 180-4 §4.1.3 — rotate/shift amounts for the message-schedule sigma
# functions (σ0, σ1) and the compression-round sigma functions (Σ0, Σ1).
comptime SIGMA0_ROT_A: UInt64 = 1
comptime SIGMA0_ROT_B: UInt64 = 8
comptime SIGMA0_SHR: UInt64 = 7

comptime SIGMA1_ROT_A: UInt64 = 19
comptime SIGMA1_ROT_B: UInt64 = 61
comptime SIGMA1_SHR: UInt64 = 6

comptime BIG_SIGMA0_ROT_A: UInt64 = 28
comptime BIG_SIGMA0_ROT_B: UInt64 = 34
comptime BIG_SIGMA0_ROT_C: UInt64 = 39

comptime BIG_SIGMA1_ROT_A: UInt64 = 14
comptime BIG_SIGMA1_ROT_B: UInt64 = 18
comptime BIG_SIGMA1_ROT_C: UInt64 = 41


# FIPS 180-4 §6.4.2 — the SHA-512 compression function (also used by
# SHA-384, SHA-512/224, and SHA-512/256).
def _compress(mut state: SIMD[DType.uint64, 8], block: InlineArray[UInt8, 128]):
    var block_span = Span(block)
    var w = InlineArray[UInt64, ROUNDS_64](uninitialized=True)
    for t in range(16):
        w[t] = load_be[DType.uint64](block_span[8 * t : 8 * t + 8])
    for t in range(16, ROUNDS_64):
        var s0 = (
            _rotr(w[t - 15], SIGMA0_ROT_A)
            ^ _rotr(w[t - 15], SIGMA0_ROT_B)
            ^ (w[t - 15] >> SIGMA0_SHR)
        )
        var s1 = (
            _rotr(w[t - 2], SIGMA1_ROT_A)
            ^ _rotr(w[t - 2], SIGMA1_ROT_B)
            ^ (w[t - 2] >> SIGMA1_SHR)
        )
        w[t] = w[t - 16] + s0 + w[t - 7] + s1

    var a = state[0]
    var b = state[1]
    var c = state[2]
    var d = state[3]
    var e = state[4]
    var f = state[5]
    var g = state[6]
    var h = state[7]

    for t in range(ROUNDS_64):
        var s1 = (
            _rotr(e, BIG_SIGMA1_ROT_A)
            ^ _rotr(e, BIG_SIGMA1_ROT_B)
            ^ _rotr(e, BIG_SIGMA1_ROT_C)
        )
        var ch = (e & f) ^ (~e & g)
        var temp1 = h + s1 + ch + K64[t] + w[t]
        var s0 = (
            _rotr(a, BIG_SIGMA0_ROT_A)
            ^ _rotr(a, BIG_SIGMA0_ROT_B)
            ^ _rotr(a, BIG_SIGMA0_ROT_C)
        )
        var maj = (a & b) ^ (a & c) ^ (b & c)
        var temp2 = s0 + maj

        h = g
        g = f
        f = e
        e = d + temp1
        d = c
        c = b
        b = a
        a = temp1 + temp2

    state[0] += a
    state[1] += b
    state[2] += c
    state[3] += d
    state[4] += e
    state[5] += f
    state[6] += g
    state[7] += h


@always_inline
def _rotr(x: UInt64, n: UInt64) -> UInt64:
    return (x >> n) | (x << (64 - n))
