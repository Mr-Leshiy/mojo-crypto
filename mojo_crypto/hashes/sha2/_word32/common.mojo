from std.memory import unsafe_memcpy
from std.math import min

from mojo_crypto.hashes.traits import Digest
from mojo_crypto.utils import load_be

comptime SHA2_WORD32_BLOCK_SIZE: Int = 64


struct _Sha2Word32[
    H0: UInt32,
    H1: UInt32,
    H2: UInt32,
    H3: UInt32,
    H4: UInt32,
    H5: UInt32,
    H6: UInt32,
    H7: UInt32,
    DigestSize: Int,
    compress: def(
        mut state: SIMD[DType.uint32, 8],
        block: InlineArray[UInt8, SHA2_WORD32_BLOCK_SIZE],
    ) thin,
](Copyable, Digest, ImplicitlyDeletable, Movable):
    """
    Naive **SHA-2 (32-bit word)** engine — FIPS 180-4 §6.2.

    Backs SHA-224 and SHA-256, which differ only in the initial hash value
    (`H0..H7`) and output truncation (`DigestSize`); the Merkle-Damgard
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
                Self.compress(self._state, self._buffer)
                self._buffer_len = 0

        while len(input) >= Self.BLOCK_SIZE:
            var block = InlineArray[UInt8, Self.BLOCK_SIZE](uninitialized=True)
            unsafe_memcpy(
                dest=block.unsafe_ptr(),
                src=input.unsafe_ptr(),
                count=Self.BLOCK_SIZE,
            )
            Self.compress(self._state, block)
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
