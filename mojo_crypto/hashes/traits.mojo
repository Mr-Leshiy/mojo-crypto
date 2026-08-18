trait Digest:
    comptime BLOCK_SIZE: Int
    """Size of the compression function's input block, in bytes."""

    comptime OUTPUT_SIZE: Int
    """
    Size of the digest `finalize` returns, in bytes.
    """

    def __init__(out self):
        """Initialize the hash to its initial state."""
        ...

    def update[o: Origin](mut self, data: Span[UInt8, o]):
        """Absorb more input."""
        ...

    def finalize(var self) -> Array[UInt8, Self.OUTPUT_SIZE]:
        """Consume self and return the OUTPUT_SIZE-byte digest."""
        ...

    def reset(mut self):
        """Reset the hash to its initial state."""
        ...


trait Xof:
    """An extendable-output function: a hash with arbitrary-length output."""

    comptime BLOCK_SIZE: Int
    """Size of the sponge's absorption block (its rate), in bytes."""

    def __init__(out self):
        """Initialize to the initial state."""
        ...

    def update[o: Origin](mut self, data: Span[UInt8, o]):
        """Absorb more input. Must not be called once `squeeze` has been."""
        ...

    def squeeze[o: MutOrigin](mut self, data: Span[UInt8, o]):
        """Fill `data` with the next `len(data)` bytes of output.

        The first call ends the absorbing phase; `update` may not be called
        after. Repeated calls continue squeezing where the previous one left
        off, so the output is independent of how it is chunked.
        """
        ...

    def reset(mut self):
        """Reset to the initial state."""
        ...
