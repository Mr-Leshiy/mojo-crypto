from std.memory import unsafe_memcpy
from std.math import min

from mojo_crypto.hashes.traits import Digest
from mojo_crypto.utils import load_be

struct _Sha2Naive32[
    H0: UInt32,
    H1: UInt32,
    H2: UInt32,
    H3: UInt32,
    H4: UInt32,
    H5: UInt32,
    H6: UInt32,
    H7: UInt32,
    DigestSize: Int,
](Copyable, Digest, ImplicitlyDeletable, Movable):
    """
    Naive, **SHA-2 (32-bit word)** engine — FIPS 180-4 §6.2.

    Backs SHA-224 and SHA-256, which differ only in the initial hash value
    (`H0..H7`) and output truncation (`DigestSize`); the Merkle-Damgard
    structure, message schedule, and compression function are identical.
    """

    comptime BLOCK_SIZE: Int = 64
    comptime OUTPUT_SIZE: Int = Self.DigestSize

    var _state: SIMD[DType.uint32, 8]
    var _buffer: InlineArray[UInt8, Self.BLOCK_SIZE]
    var _buffer_len: Int
    var _total_len: UInt64

    def __init__(out self):
        self._state = Self._iv()
        self._buffer = InlineArray[UInt8, Self.BLOCK_SIZE](uninitialized=True)
        self._buffer_len = 0
        self._total_len = 0

    @staticmethod
    def _iv() -> SIMD[DType.uint32, 8]:
        return SIMD[DType.uint32, 8](
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

        # FIPS 180-4 §5.1.1: append 0x80, zero-pad to 56 mod 64, then the
        # 64-bit big-endian bit length. If the 0x80 byte doesn't leave room
        # for the length field in this block, zero-fill and compress it
        # first, then start a fresh all-zero block for the length.
        var bit_len = self._total_len * 8

        self._buffer[self._buffer_len] = 0x80
        var pad_len = self._buffer_len + 1

        if pad_len > Self.BLOCK_SIZE - 8:
            for i in range(pad_len, Self.BLOCK_SIZE):
                self._buffer[i] = 0
            _compress(self._state, self._buffer)
            pad_len = 0

        for i in range(pad_len, Self.BLOCK_SIZE - 8):
            self._buffer[i] = 0
        for i in range(8):
            self._buffer[Self.BLOCK_SIZE - 8 + i] = UInt8(
                bit_len >> UInt64(8 * (7 - i))
            )
        _compress(self._state, self._buffer)

        var out = InlineArray[UInt8, Self.OUTPUT_SIZE](uninitialized=True)
        for i in range(Self.OUTPUT_SIZE):
            out[i] = UInt8(self._state[i // 4] >> UInt32(8 * (3 - i % 4)))
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

# FIPS 180-4 §4.1.2 — rotate/shift amounts for the message-schedule sigma
# functions (σ0, σ1) and the compression-round sigma functions (Σ0, Σ1).
comptime SIGMA0_ROT_A: UInt32 = 7
comptime SIGMA0_ROT_B: UInt32 = 18
comptime SIGMA0_SHR: UInt32 = 3

comptime SIGMA1_ROT_A: UInt32 = 17
comptime SIGMA1_ROT_B: UInt32 = 19
comptime SIGMA1_SHR: UInt32 = 10

comptime BIG_SIGMA0_ROT_A: UInt32 = 2
comptime BIG_SIGMA0_ROT_B: UInt32 = 13
comptime BIG_SIGMA0_ROT_C: UInt32 = 22

comptime BIG_SIGMA1_ROT_A: UInt32 = 6
comptime BIG_SIGMA1_ROT_B: UInt32 = 11
comptime BIG_SIGMA1_ROT_C: UInt32 = 25


# FIPS 180-4 §6.2.2 — the SHA-256 compression function (also used by SHA-224).
def _compress(mut state: SIMD[DType.uint32, 8], block: InlineArray[UInt8, 64]):
    var block_span = Span(block)
    var w = InlineArray[UInt32, ROUNDS_32](uninitialized=True)
    for t in range(16):
        w[t] = load_be[DType.uint32](block_span[4 * t : 4 * t + 4])
    for t in range(16, ROUNDS_32):
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

    for t in range(ROUNDS_32):
        var s1 = (
            _rotr(e, BIG_SIGMA1_ROT_A)
            ^ _rotr(e, BIG_SIGMA1_ROT_B)
            ^ _rotr(e, BIG_SIGMA1_ROT_C)
        )
        var ch = (e & f) ^ (~e & g)
        var temp1 = h + s1 + ch + K32[t] + w[t]
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
def _rotr(x: UInt32, n: UInt32) -> UInt32:
    return (x >> n) | (x << (32 - n))
