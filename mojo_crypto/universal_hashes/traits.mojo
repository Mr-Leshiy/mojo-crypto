trait UniversalHashable:
    comptime BLOCK_SIZE: Int
    comptime KEY_SIZE: Int
    comptime TAG_SIZE: Int

    # Absorb whole BLOCK_SIZE-aligned input. Raises UhashSizeError if
    # len(data) is not a multiple of BLOCK_SIZE — padding is the caller's job.
    def update[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        ...

    # Consume the accumulator and return the TAG_SIZE-byte result.
    # Takes var self so the hash cannot be reused after finalization.
    def finalize(var self) -> InlineArray[UInt8, Self.TAG_SIZE]:
        ...
