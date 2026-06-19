trait AeadEncryptable:
    """
    Encryption of an AEAD scheme.

    Provides confidentiality for `data` and integrity for both `data` and the
    associated data `aad`, producing a `tag_size`-byte tag.
    """

    def encrypt[
        tag_size: Int, aad_o: Origin, o: MutOrigin
    ](
        mut self, aad: Span[UInt8, aad_o], data: Span[UInt8, o]
    ) raises -> InlineArray[UInt8, tag_size]:
        """Encrypt `data` in place and return the `tag_size`-byte tag."""
        ...


trait AeadDecryptable:
    """
    Decryption of an AEAD scheme.

    Verifies a `tag_size`-byte tag over `aad` and the ciphertext `data`, then
    decrypts `data` in place.
    """

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
