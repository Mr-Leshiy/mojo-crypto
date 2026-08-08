from std.math import min

from mojo_crypto.block_ciphers.traits import BlockCipherEncryptable
from mojo_crypto.macs.traits import Mac
from mojo_crypto.utils import to_bytes


struct Cmac[Cipher: BlockCipherEncryptable & Copyable & Deinitable](
    Copyable, Deinitable, Mac, Movable
):
    """
    **CMAC** (OMAC1): a cipher-based message authentication code.

    CMAC turns any block cipher into a MAC by chaining input blocks through
    the cipher like CBC-MAC, then masking the final block with one of two
    subkeys derived from the cipher itself. The subkey mask is what closes
    CBC-MAC's classic forgery on variable-length messages.

    NIST SP 800-38B:
    https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38b.pdf
    RFC 4493 (AES-CMAC):
    https://www.rfc-editor.org/rfc/rfc4493
    """

    comptime BLOCK_SIZE: Int = Self.Cipher.BLOCK_SIZE
    comptime TAG_SIZE: Int = Self.BLOCK_SIZE

    var _cipher: Self.Cipher
    var _state: SIMD[DType.uint8, Self.BLOCK_SIZE]

    # Lazily-buffered tail of the input: `update` always holds back the final
    # block (even when it is full) so `finalize` can tell whether to mask it
    # with K1 (full block) or K2 (partial, 10*-padded).
    var _last_message_block: Array[UInt8, Self.BLOCK_SIZE]
    var _last_message_block_len: Int

    def __init__(out self, var cipher: Self.Cipher):
        """Initialize CMAC from an already-keyed block cipher."""
        Self._assert_valid_params()
        self._cipher = cipher^
        self._state = SIMD[DType.uint8, Self.BLOCK_SIZE](0)
        self._last_message_block = Array[UInt8, Self.BLOCK_SIZE](
            uninitialized=True
        )
        self._last_message_block_len = 0

    @staticmethod
    def _assert_valid_params():
        comptime assert (
            Self.BLOCK_SIZE == 8 or Self.BLOCK_SIZE == 16
        ), "CMAC is only defined for 64-bit or 128-bit block ciphers"

    def _absorb_block(
        mut self, block: SIMD[DType.uint8, Self.BLOCK_SIZE]
    ) raises:
        self._state ^= block
        # The cipher works on bytes, so the state goes through a byte array
        # and back rather than the vector's storage being aliased as one.
        var state_bytes = to_bytes[
            input_size=Self.BLOCK_SIZE, output_size=Self.BLOCK_SIZE
        ](self._state)
        self._cipher.encrypt(state_bytes)
        self._state = SIMD[DType.uint8, Self.BLOCK_SIZE].from_bytes(state_bytes)

    def update[o: Origin](mut self, data: Span[UInt8, o]) raises:
        """Absorb more input."""
        var input = data

        # A prior `update` call already left a tail buffered here — it held
        # it back because it didn't yet know whether it was the message's
        # last block. New data just arrived, so top it off before deciding.
        if self._last_message_block_len > 0:
            # Only take enough bytes to fill the buffer up to BLOCK_SIZE —
            # never more, even if `input` has plenty left — since anything
            # beyond that belongs to later blocks, not this tail.
            var take = min(
                Self.BLOCK_SIZE - self._last_message_block_len, len(input)
            )
            self._tail_span(take).copy_from(input[:take])
            self._last_message_block_len += take
            input = input[take:]

            # The buffer is now a full block — but it's only safe to absorb
            # if more input follows. If `input` is empty, this buffered
            # block might be the message's actual last block, which must
            # stay untouched for `finalize` to mask with K1/K2.
            if (
                self._last_message_block_len == Self.BLOCK_SIZE
                and len(input) > 0
            ):
                self._absorb_block(
                    SIMD[DType.uint8, Self.BLOCK_SIZE].from_bytes(
                        self._last_message_block
                    )
                )
                self._last_message_block_len = 0

        while len(input) > Self.BLOCK_SIZE:
            # `input` has a runtime length, so `SIMD.from_bytes` — which needs
            # a fixed-size array — only applies after the block is copied out.
            var block = Array[UInt8, Self.BLOCK_SIZE](uninitialized=True)
            Span(block).copy_from(input[: Self.BLOCK_SIZE])
            self._absorb_block(
                SIMD[DType.uint8, Self.BLOCK_SIZE].from_bytes(block)
            )
            input = input[Self.BLOCK_SIZE :]

        # Fill `_last_message_block` with the tail, for `finalize` to mask
        # with K1/K2.
        if len(input) > 0:
            self._tail_span(len(input)).copy_from(input)
            self._last_message_block_len += len(input)

    @always_inline
    def _tail_span(
        mut self, count: Int
    ) -> Span[UInt8, origin_of(self._last_message_block)]:
        """The `count` free tail-buffer bytes after the buffered prefix."""
        var start = self._last_message_block_len
        return Span(self._last_message_block)[start : start + count]

    def finalize(var self) raises -> Array[UInt8, Self.TAG_SIZE]:
        """
        Consume self and return the TAG_SIZE-byte authentication tag.

        Derives K1 (and K2, if the buffered final block turned out to be
        partial) per NIST SP 800-38B's subkey generation algorithm, masks the
        buffered final block with it, and runs one more cipher block to
        produce the tag.
        """

        var subkey = Array[UInt8, Self.BLOCK_SIZE](fill=0)
        self._cipher.encrypt(subkey)
        var k1 = _dbl(subkey^)

        # Zero-pad the buffered tail into a full block; only the first
        # `_last_message_block_len` bytes of `_last_message_block` are
        # meaningful.
        var padded = Array[UInt8, Self.BLOCK_SIZE](fill=0)
        var tail_len = self._last_message_block_len
        Span(padded)[:tail_len].copy_from(
            Span(self._last_message_block)[:tail_len]
        )

        var last: Array[UInt8, Self.BLOCK_SIZE]
        if self._last_message_block_len == Self.BLOCK_SIZE:
            var padded_simd = SIMD[DType.uint8, Self.BLOCK_SIZE].from_bytes(
                padded
            )
            var k1_simd = SIMD[DType.uint8, Self.BLOCK_SIZE].from_bytes(k1)
            last = to_bytes[
                input_size=Self.BLOCK_SIZE, output_size=Self.BLOCK_SIZE
            ](self._state ^ padded_simd ^ k1_simd)
        else:
            padded[self._last_message_block_len] ^= 0x80
            var padded_simd = SIMD[DType.uint8, Self.BLOCK_SIZE].from_bytes(
                padded
            )
            var k2 = _dbl(k1^)
            var k2_simd = SIMD[DType.uint8, Self.BLOCK_SIZE].from_bytes(k2)
            last = to_bytes[
                input_size=Self.BLOCK_SIZE, output_size=Self.BLOCK_SIZE
            ](self._state ^ padded_simd ^ k2_simd)

        self._cipher.encrypt(last)
        return last^

    def reset(mut self):
        """Reset the accumulator to its initial state while keeping the key."""
        self._state = SIMD[DType.uint8, Self.BLOCK_SIZE](0)
        self._last_message_block_len = 0


def _dbl[
    BLOCK_SIZE: Int
](var block: Array[UInt8, BLOCK_SIZE]) -> Array[UInt8, BLOCK_SIZE]:
    """
    Double `block` over GF(2^(8*BLOCK_SIZE)) (NIST SP 800-38B's `dbl`
    operation, big-endian).

    Left-shifts the block by one bit; if the vacated MSB was 1, XORs the
    field's reduction constant into the trailing byte (0x87 for 128-bit
    blocks, 0x1B for 64-bit blocks — NIST SP 800-38B Table in App. 2.3).
    """
    comptime R: UInt8 = 0x87 if BLOCK_SIZE == 16 else 0x1B

    var msb = block[0] >> 7
    for i in range(BLOCK_SIZE - 1):
        block[i] = (block[i] << 1) | (block[i + 1] >> 7)
    block[BLOCK_SIZE - 1] = block[BLOCK_SIZE - 1] << 1
    if msb == 1:
        block[BLOCK_SIZE - 1] ^= R
    return block^
