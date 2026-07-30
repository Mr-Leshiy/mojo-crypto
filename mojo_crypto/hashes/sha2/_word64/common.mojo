from std.memory import unsafe_memcpy
from std.math import min

from mojo_crypto.hashes.traits import Digest
from mojo_crypto.utils import load_be

comptime SHA2_WORD64_BLOCK_SIZE: Int = 128

# FIPS 180-4 §5.3.4 — SHA-384 initial hash value.
comptime SHA384_IV: InlineArray[UInt64, 8] = [
    # fmt: off
    0xCBBB9D5DC1059ED8, 0x629A292A367CD507, 0x9159015A3070DD17, 0x152FECD8F70E5939,
    0x67332667FFC00B31, 0x8EB44A8768581511, 0xDB0C2E0D64F98FA7, 0x47B5481DBEFA4FA4,
    # fmt: on
]

# FIPS 180-4 §5.3.5 — SHA-512 initial hash value.
comptime SHA512_IV: InlineArray[UInt64, 8] = [
    # fmt: off
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
    # fmt: on
]

# FIPS 180-4 §5.3.6.1 — SHA-512/224 initial hash value.
comptime SHA512_224_IV: InlineArray[UInt64, 8] = [
    # fmt: off
    0x8C3D37C819544DA2, 0x73E1996689DCD4D6, 0x1DFAB7AE32FF9C82, 0x679DD514582F9FCF,
    0x0F6D2B697BD44DA8, 0x77E36F7304C48942, 0x3F9D85A86A1D36C8, 0x1112E6AD91D692A1,
    # fmt: on
]

# FIPS 180-4 §5.3.6.2 — SHA-512/256 initial hash value.
comptime SHA512_256_IV: InlineArray[UInt64, 8] = [
    # fmt: off
    0x22312194FC2BF72C, 0x9F555FA3C84C64C2, 0x2393B86B6F53B151, 0x963877195940EABD,
    0x96283EE2A88EFFE3, 0xBE5E1E2553863992, 0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2,
    # fmt: on
]


struct _Sha2Word64[
    IV: InlineArray[UInt64, 8],
    DigestSize: Int,
    compress: def(
        mut state: SIMD[DType.uint64, 8],
        block: InlineArray[UInt8, SHA2_WORD64_BLOCK_SIZE],
    ) thin,
](Copyable, Digest, ImplicitlyDeletable, Movable):
    """
    Naive **SHA-2 (64-bit word)** engine — FIPS 180-4 §6.4.

    Backs SHA-384, SHA-512, SHA-512/224, and SHA-512/256, which differ only
    in the initial hash value (`IV`) and output truncation (`DigestSize`);
    the Merkle-Damgard structure, message schedule, and compression function
    are identical.
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
        var iv = SIMD[DType.uint64, 8](0)
        comptime for i in range(8):
            iv[i] = Self.IV[i]
        return iv

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
