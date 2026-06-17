trait UniversalHashable:
    comptime BLOCK_SIZE: Int
    comptime KEY_SIZE: Int
    comptime TAG_SIZE: Int

    def __init__(out self, h: InlineArray[UInt8, Self.KEY_SIZE]):
        """Initialize the hash from a KEY_SIZE-byte key."""
        ...

    def update_block(mut self, block: InlineArray[UInt8, Self.BLOCK_SIZE]):
        """Absorb a single BLOCK_SIZE block."""
        ...

    def update[o: Origin](mut self, data: Span[UInt8, o]) raises:
        """
        Absorb whole BLOCK_SIZE-aligned input.

        Raises UhashSizeError if len(data) is not a multiple of BLOCK_SIZE —
        padding is the caller's job.
        """

        UhashSizeError[Self.BLOCK_SIZE].check(len(data))
        for i in range(len(data) // Self.BLOCK_SIZE):
            var block = InlineArray[UInt8, Self.BLOCK_SIZE](uninitialized=True)
            block.unsafe_ptr().store(
                (data.unsafe_ptr() + i * Self.BLOCK_SIZE).load[
                    width=Self.BLOCK_SIZE
                ]()
            )
            self.update_block(block)

    def update_padded[o: Origin](mut self, data: Span[UInt8, o]) raises:
        """
        Absorb input of any length, zero-padding the final partial block if needed.

        Full blocks are passed directly to update_block; if the input length is
        not a multiple of BLOCK_SIZE the remaining bytes are copied into a
        zero-filled block before being absorbed. Frequently used by AEAD modes
        whose MACs are based on universal hashing (e.g. AES-GCM, AES-GCM-SIV).
        """

        tail_len = len(data) % Self.BLOCK_SIZE
        n_full = len(data) - tail_len
        self.update(data[:n_full])
        if tail_len > 0:
            var padded = InlineArray[UInt8, Self.BLOCK_SIZE](fill=0)
            for i in range(tail_len):
                padded[i] = data[n_full + i]
            self.update_block(padded)

    def finalize(var self) -> InlineArray[UInt8, Self.TAG_SIZE]:
        """Consume self and return the TAG_SIZE-byte authentication tag."""
        ...
