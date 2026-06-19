trait Aead:
    """Authenticated Encryption with Associated Data.

    An AEAD scheme provides confidentiality for `data` and integrity for both
    `data` and the associated data `aad`, producing a `tag_size`-byte tag.

    The tag length is a parameter of `encrypt`/`decrypt` rather than an
    associated constant of the trait: a concrete scheme is free to fix it to a
    single value (see `Gcm`, which pins `tag_size` to its own `TAG_SIZE`).
    """

    def encrypt[
        tag_size: Int, aad_o: Origin, o: MutOrigin
    ](
        mut self, aad: Span[UInt8, aad_o], data: Span[UInt8, o]
    ) raises -> InlineArray[UInt8, tag_size]:
        """Encrypt `data` in place and return the `tag_size`-byte tag."""
        ...

    def decrypt[
        tag_size: Int, aad_o: Origin, o: MutOrigin
    ](
        mut self,
        aad: Span[UInt8, aad_o],
        data: Span[UInt8, o],
        tag: InlineArray[UInt8, tag_size],
    ) raises:
        """Verify `tag`, then decrypt `data` in place."""
        ...
