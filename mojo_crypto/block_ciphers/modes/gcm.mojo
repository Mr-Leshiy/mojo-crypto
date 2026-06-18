from mojo_crypto.block_ciphers.traits import (
    BlockCipherDecryptable,
    BlockCipherEncryptable,
)


struct GcmMode[
    Cipher: BlockCipherEncryptable
    & BlockCipherDecryptable
    & Movable
    & ImplicitlyDestructible
](ImplicitlyDestructible):
    """Galois/Counter Mode (GCM) authenticated encryption.

    GCM combines counter (CTR) mode for confidentiality with GHASH for
    authentication.

    Note:
        GCM is defined only for block ciphers with a 128-bit block size. 

    NIST SP 800-38D:
    https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
    """


    comptime BLOCK_SIZE: Int = Self.Cipher.BLOCK_SIZE

    var _cipher: Self.Cipher

    def __init__(out self, var cipher: Self.Cipher):
        """Initialize the GCM mode with the given block cipher."""
        comptime assert (
            Self.BLOCK_SIZE == 16
        ), "GCM is defined only for 128-bit (16-byte) block ciphers"
        self._cipher = cipher^
