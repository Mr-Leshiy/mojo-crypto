trait Aead:
    """Authenticated Encryption with Associated Data.

    An AEAD scheme provides confidentiality for `data` and integrity for both
    `data` and the associated data `aad`, producing a `TAG_SIZE`-byte tag.
    """

    comptime TAG_SIZE: Int

    def encrypt[
        aad_o: Origin, o: MutOrigin
    ](
        mut self, aad: Span[UInt8, aad_o], data: Span[UInt8, o]
    ) raises -> InlineArray[UInt8, Self.TAG_SIZE]:
        """Encrypt `data` in place and return the `TAG_SIZE`-byte tag."""
        ...

    def decrypt[
        aad_o: Origin, o: MutOrigin
    ](
        mut self,
        aad: Span[UInt8, aad_o],
        data: Span[UInt8, o],
        tag: InlineArray[UInt8, Self.TAG_SIZE],
    ) raises:
        """Verify `tag`, then decrypt `data` in place."""
        ...
