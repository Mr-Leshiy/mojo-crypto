trait UniversalHashable:
    comptime BLOCK_SIZE: Int
    comptime KEY_SIZE: Int
    comptime TAG_SIZE: Int

    # Absorb whole BLOCK_SIZE-aligned input. Raises UhashSizeError if
    # len(data) is not a multiple of BLOCK_SIZE — padding is the caller's job.
    def update[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        ...

    # Return the TAG_SIZE-byte result.
    def finalize(self) -> InlineArray[UInt8, Self.TAG_SIZE]:
        ...
