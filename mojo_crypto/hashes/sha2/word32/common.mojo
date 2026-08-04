from std.math import min

from mojo_crypto.hashes.traits import Digest
from mojo_crypto.utils import load_be

comptime SHA2_WORD32_BLOCK_SIZE: Int = 64

# FIPS 180-4 §6.2.2 — number of rounds in the 32-bit-word compression
# function (SHA-224/256), and thus the size of the expanded message schedule
# and of the K32 table below.
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

# FIPS 180-4 §5.3.2 — SHA-224 initial hash value.
comptime SHA224_IV: InlineArray[UInt32, 8] = [
    0xC1059ED8,
    0x367CD507,
    0x3070DD17,
    0xF70E5939,
    0xFFC00B31,
    0x68581511,
    0x64F98FA7,
    0xBEFA4FA4,
]

# FIPS 180-4 §5.3.3 — SHA-256 initial hash value.
comptime SHA256_IV: InlineArray[UInt32, 8] = [
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
]


struct _Sha2Word32[
    IV: InlineArray[UInt32, 8],
    DigestSize: Int,
    compress: def(
        mut state: SIMD[DType.uint32, 8],
        block: InlineArray[UInt8, SHA2_WORD32_BLOCK_SIZE],
    ) thin,
](Copyable, Deinitable, Digest, Movable):
    """
    Naive **SHA-2 (32-bit word)** engine — FIPS 180-4 §6.2.

    Backs SHA-224 and SHA-256, which differ only in the initial hash value
    (`IV`) and output truncation (`DigestSize`); the Merkle-Damgard
    structure, message schedule, and compression function are identical.
    """

    comptime BLOCK_SIZE: Int = SHA2_WORD32_BLOCK_SIZE
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
    @always_inline
    def _iv() -> SIMD[DType.uint32, 8]:
        return comptime (
            SIMD[DType.uint32, 8](
                Self.IV[0],
                Self.IV[1],
                Self.IV[2],
                Self.IV[3],
                Self.IV[4],
                Self.IV[5],
                Self.IV[6],
                Self.IV[7],
            )
        )

    def update[o: Origin](mut self, data: Span[UInt8, o]):
        """Absorb more input."""
        var input = data
        self._total_len += UInt64(len(input))

        # A prior `update` call left a partial block buffered — top it off
        # before deciding whether it is now full.
        if self._buffer_len > 0:
            var take = min(Self.BLOCK_SIZE - self._buffer_len, len(input))
            self._buffer_span(take).copy_from(input[:take])
            self._buffer_len += take
            input = input[take:]
            if self._buffer_len == Self.BLOCK_SIZE:
                Self.compress(self._state, self._buffer)
                self._buffer_len = 0

        while len(input) >= Self.BLOCK_SIZE:
            var block = InlineArray[UInt8, Self.BLOCK_SIZE](uninitialized=True)
            Span(block).copy_from(input[: Self.BLOCK_SIZE])
            Self.compress(self._state, block)
            input = input[Self.BLOCK_SIZE :]

        if len(input) > 0:
            self._buffer_span(len(input)).copy_from(input)
            self._buffer_len += len(input)

    @always_inline
    def _buffer_span(
        mut self, count: Int
    ) -> Span[UInt8, origin_of(self._buffer)]:
        """The `count` free buffer bytes starting at the buffered prefix."""
        return Span(self._buffer)[self._buffer_len : self._buffer_len + count]

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
            Self.compress(self._state, self._buffer)
            pad_len = 0

        for i in range(pad_len, Self.BLOCK_SIZE - 8):
            self._buffer[i] = 0
        for i in range(8):
            self._buffer[Self.BLOCK_SIZE - 8 + i] = UInt8(
                bit_len >> UInt64(8 * (7 - i))
            )
        Self.compress(self._state, self._buffer)

        var out = InlineArray[UInt8, Self.OUTPUT_SIZE](uninitialized=True)
        for i in range(Self.OUTPUT_SIZE):
            out[i] = UInt8(self._state[i // 4] >> UInt32(8 * (3 - i % 4)))
        return out^

    def reset(mut self):
        """Reset the hash to its initial state."""
        self._state = Self._iv()
        self._buffer_len = 0
        self._total_len = 0
