from std.memory import memcpy
from std.math import min

from mojo_crypto.hashes.traits import Digest

from ._common import K64, ROUNDS_64


struct Sha2Cpu64[
    H0: UInt64,
    H1: UInt64,
    H2: UInt64,
    H3: UInt64,
    H4: UInt64,
    H5: UInt64,
    H6: UInt64,
    H7: UInt64,
    DigestSize: Int,
](Copyable, Digest, ImplicitlyDestructible, Movable):
    """
    Naive, portable **SHA-2 (64-bit word)** engine — FIPS 180-4 §6.4.

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
            memcpy(
                dest=self._buffer.unsafe_ptr() + self._buffer_len,
                src=input.unsafe_ptr(),
                count=take,
            )
            self._buffer_len += take
            input = input[take:]
            if self._buffer_len == Self.BLOCK_SIZE:
                _compress(self._state, self._buffer)
                self._buffer_len = 0

        while len(input) >= Self.BLOCK_SIZE:
            var block = InlineArray[UInt8, Self.BLOCK_SIZE](
                uninitialized=True
            )
            memcpy(
                dest=block.unsafe_ptr(),
                src=input.unsafe_ptr(),
                count=Self.BLOCK_SIZE,
            )
            _compress(self._state, block)
            input = input[Self.BLOCK_SIZE :]

        if len(input) > 0:
            memcpy(
                dest=self._buffer.unsafe_ptr() + self._buffer_len,
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
            out[i] = UInt8(
                self._state[i // 8] >> UInt64(8 * (7 - i % 8))
            )
        return out^

    def reset(mut self):
        """Reset the hash to its initial state."""
        self._state = Self._iv()
        self._buffer_len = 0
        self._total_len = 0


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
def _compress(
    mut state: SIMD[DType.uint64, 8], block: InlineArray[UInt8, 128]
):
    var w = InlineArray[UInt64, ROUNDS_64](uninitialized=True)
    for t in range(16):
        var i = 8 * t
        var word: UInt64 = 0
        for j in range(8):
            word = (word << 8) | UInt64(block[i + j])
        w[t] = word
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
