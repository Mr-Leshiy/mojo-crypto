from std.memory import unsafe_memcpy
from std.math import min

from mojo_crypto.hashes.traits import Digest
from mojo_crypto.utils import load_be

comptime SHA2_WORD64_BLOCK_SIZE: Int = 128


struct _Sha2Word64[
    H0: UInt64,
    H1: UInt64,
    H2: UInt64,
    H3: UInt64,
    H4: UInt64,
    H5: UInt64,
    H6: UInt64,
    H7: UInt64,
    DigestSize: Int,
    compress: def(
        mut state: SIMD[DType.uint64, 8],
        block: InlineArray[UInt8, SHA2_WORD64_BLOCK_SIZE],
    ) thin,
](Copyable, Digest, ImplicitlyDeletable, Movable):
    """
    Naive **SHA-2 (64-bit word)** engine — FIPS 180-4 §6.4.

    Backs SHA-384, SHA-512, SHA-512/224, and SHA-512/256, which differ only
    in the initial hash value (`H0..H7`) and output truncation
    (`DigestSize`); the Merkle-Damgard structure, message schedule, and
    compression function are identical.
    """

    comptime BLOCK_SIZE: Int = SHA2_WORD64_BLOCK_SIZE
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
            Self.compress(self._state, self._buffer)
            pad_len = 0

        for i in range(pad_len, Self.BLOCK_SIZE - 16):
            self._buffer[i] = 0
        for i in range(8):
            self._buffer[Self.BLOCK_SIZE - 16 + i] = 0
        for i in range(8):
            self._buffer[Self.BLOCK_SIZE - 8 + i] = UInt8(
                bit_len >> UInt64(8 * (7 - i))
            )
        Self.compress(self._state, self._buffer)

        var out = InlineArray[UInt8, Self.OUTPUT_SIZE](uninitialized=True)
        for i in range(Self.OUTPUT_SIZE):
            out[i] = UInt8(self._state[i // 8] >> UInt64(8 * (7 - i % 8)))
        return out^

    def reset(mut self):
        """Reset the hash to its initial state."""
        self._state = Self._iv()
        self._buffer_len = 0
        self._total_len = 0
