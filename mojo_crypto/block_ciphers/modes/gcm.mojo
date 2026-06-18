from mojo_crypto.block_ciphers.traits import (
    BlockCipherDecryptable,
    BlockCipherEncryptable,
)
from mojo_crypto.block_ciphers.modes import CtrMode
from mojo_crypto.utils import target_triple_contains_any
from mojo_crypto.universal_hashes.traits import UniversalHashable


struct GcmMode[
    Cipher: BlockCipherEncryptable
    & BlockCipherDecryptable
    & Movable
    & ImplicitlyDestructible,
    G: UniversalHashable & Movable & ImplicitlyDestructible,
    NONCE_SIZE: Int,
    TAG_SIZE: Int,
](ImplicitlyDestructible, Movable):
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
    var _ghash: Self.G
    var _nonce: InlineArray[UInt8, Self.NONCE_SIZE]

    def __init__(
        out self,
        var cipher: Self.Cipher,
        nonce: InlineArray[UInt8, Self.NONCE_SIZE],
    ) raises:
        """Initialize the GCM mode with the given block cipher and nonce."""
        comptime assert (
            Self.BLOCK_SIZE == 16
        ), "GCM is defined only for 128-bit (16-byte) block ciphers"
        comptime assert (
            Self.TAG_SIZE > 0 and Self.TAG_SIZE <= Self.BLOCK_SIZE
        ), "GCM TAG_SIZE must be between 1 and 16 bytes"
        comptime assert Self.NONCE_SIZE > 0, "GCM NONCE_SIZE must be positive"

        ghash_key = InlineArray[UInt8, Self.G.KEY_SIZE](fill=0)
    
        self._cipher = cipher^
        self._nonce = nonce

    def encrypt[
        aad_o: Origin, o: MutOrigin
    ](
        mut self, aad: Span[UInt8, aad_o], data: Span[UInt8, o]
    ) raises -> InlineArray[UInt8, Self.TAG_SIZE]:
        """Encrypt `data` in place and return the `TAG_SIZE`-byte tag.

        The counter starts at inc32(J0); GHASH then authenticates `aad` together
        with the freshly produced ciphertext.
        """


    def decrypt[
        aad_o: Origin, o: MutOrigin
    ](
        mut self,
        aad: Span[UInt8, aad_o],
        data: Span[UInt8, o],
        tag: InlineArray[UInt8, Self.TAG_SIZE],
    ) raises:
        """Verify `tag`, then decrypt `data` in place.

        The tag is recomputed over `aad` and the input ciphertext and compared
        in constant time. On mismatch this raises and `data` is left untouched.
        """

