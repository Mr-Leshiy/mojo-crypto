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
