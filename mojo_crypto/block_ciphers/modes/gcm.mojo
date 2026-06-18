from mojo_crypto.block_ciphers.traits import (
    BlockCipherDecryptable,
    BlockCipherEncryptable,
)


struct GcmMode[
    Cipher: BlockCipherEncryptable
    & BlockCipherDecryptable
    & Movable
    & ImplicitlyDestructible,
    NONCE_SIZE: Int,
    TAG_SIZE: Int,
](ImplicitlyDestructible, Movable):
    """Galois/Counter Mode (GCM) authenticated encryption.

    GCM combines counter (CTR) mode for confidentiality with GHASH for
    authentication.

    Parameters:
        Cipher: The underlying block cipher (must have a 128-bit block).
        NONCE_SIZE: Nonce/IV length in bytes (commonly 12).
        TAG_SIZE: Authentication tag length in bytes (at most 16; GCM keeps the
            leftmost bytes when truncated).

    Note:
        GCM is defined only for block ciphers with a 128-bit block size.

    NIST SP 800-38D:
    https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
    """

    comptime BLOCK_SIZE: Int = Self.Cipher.BLOCK_SIZE

    var _cipher: Self.Cipher
    var _nonce: InlineArray[UInt8, Self.NONCE_SIZE]

    def __init__(
        out self,
        var cipher: Self.Cipher,
        nonce: InlineArray[UInt8, Self.NONCE_SIZE],
    ):
        """Initialize the GCM mode with the given block cipher and nonce."""
        comptime assert (
            Self.BLOCK_SIZE == 16
        ), "GCM is defined only for 128-bit (16-byte) block ciphers"
        comptime assert (
            Self.TAG_SIZE > 0 and Self.TAG_SIZE <= Self.BLOCK_SIZE
        ), "GCM TAG_SIZE must be between 1 and 16 bytes"
        comptime assert Self.NONCE_SIZE > 0, "GCM NONCE_SIZE must be positive"
        self._cipher = cipher^
        self._nonce = nonce

    def encrypt[
        aad_o: Origin, o: MutOrigin
    ](
        mut self, aad: Span[UInt8, aad_o], data: Span[UInt8, o]
    ) raises -> InlineArray[UInt8, Self.TAG_SIZE]:
        """Encrypt `data` in place and return the `TAG_SIZE`-byte tag.

        Note:
            Not implemented yet — only the interface is defined.
        """
        raise Error("GcmMode.encrypt is not implemented yet")

    def decrypt[
        aad_o: Origin, o: MutOrigin
    ](
        mut self,
        aad: Span[UInt8, aad_o],
        data: Span[UInt8, o],
        tag: InlineArray[UInt8, Self.TAG_SIZE],
    ) raises:
        """Verify `tag`, then decrypt `data` in place.

        Raises on authentication failure.

        Note:
            Not implemented yet — only the interface is defined.
        """
        raise Error("GcmMode.decrypt is not implemented yet")
