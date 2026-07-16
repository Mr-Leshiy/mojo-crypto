trait Mac:
    comptime TAG_SIZE: Int

    def update[o: Origin](mut self, data: Span[UInt8, o]) raises:
        """Absorb more input."""
        ...

    def finalize(var self) raises -> InlineArray[UInt8, Self.TAG_SIZE]:
        """Consume self and return the TAG_SIZE-byte authentication tag."""
        ...

    def reset(mut self):
        """Reset the accumulator to its initial state while keeping the key."""
        ...
