from mojo_crypto.aead.traits import AeadDecryptable, AeadEncryptable
from mojo_crypto.aead.errors import AuthenticationError
from mojo_crypto.block_ciphers.traits import (
    BlockCipherDecryptable,
    BlockCipherEncryptable,
)
from mojo_crypto.block_ciphers.modes import CtrMode
from mojo_crypto.universal_hashes.traits import UniversalHashable


struct GcmSiv[
    Cipher: BlockCipherEncryptable
    & BlockCipherDecryptable
    & Copyable
    & Movable
    & ImplicitlyDestructible,
    G: UniversalHashable & Copyable & Movable & ImplicitlyDestructible,
](
    AeadDecryptable,
    AeadEncryptable,
    Copyable,
    ImplicitlyDestructible,
    Movable,
):
    """
    AES-GCM-SIV nonce-misuse-resistant authenticated encryption (RFC 8452).

    Key differences from `Gcm`:

      * The nonce is fixed at 96 bits (12 bytes).
      * The tag is fixed at 128 bits (16 bytes); no truncation is permitted.
      * The cipher passed at construction is keyed with the *key-generating key*.
        The per-record message-authentication key (POLYVAL key) and
        message-encryption key are derived from that key together with the
        nonce, so they are recomputed for this instance's nonce rather than
        prebuilt the way `Gcm` prebuilds its GHASH key (H = E_K(0)).
      * Authentication uses POLYVAL (the byte-reflected dual of GHASH), not
        GHASH.

    Note:
        GCM-SIV is defined only for block ciphers with a 128-bit block size.

    RFC 8452: https://www.rfc-editor.org/rfc/rfc8452
    """

    comptime BLOCK_SIZE: Int = Self.Cipher.BLOCK_SIZE
    comptime NONCE_SIZE: Int = 12
    comptime TAG_SIZE: Int = 16

    # The key-generating key, embodied by an already-keyed cipher. Per-record
    # keys are derived from this; see `_derive_keys`.
    var _cipher: Self.Cipher
    var _nonce: InlineArray[UInt8, Self.NONCE_SIZE]

    def __init__(
        out self,
        var cipher: Self.Cipher,
        nonce: InlineArray[UInt8, Self.NONCE_SIZE],
    ) raises:
        """Initialize GCM-SIV with the key-generating-key cipher and nonce."""
        Self._assert_valid_params()

        self._cipher = cipher^
        self._nonce = nonce

    @staticmethod
    def _assert_valid_params():
        comptime assert (
            Self.BLOCK_SIZE == 16
        ), "GCM-SIV is defined only for 128-bit (16-byte) block ciphers"
        comptime assert (
            Self.G.BLOCK_SIZE == Self.BLOCK_SIZE
            and Self.G.TAG_SIZE == Self.BLOCK_SIZE
        ), (
            "GCM-SIV requires a POLYVAL whose block/tag size match the cipher"
            " block"
        )

    @staticmethod
    def _assert_tag_size[TAG_SIZE: Int]():
        # GCM-SIV does not permit tag truncation: the synthetic tag *is* the CTR
        # initial counter, so the full 16 bytes are always required.
        comptime assert (
            TAG_SIZE == Self.TAG_SIZE
        ), "GCM-SIV requires a full 16-byte tag (no truncation)"

    def encrypt[
        TAG_SIZE: Int = Self.TAG_SIZE, aad_o: Origin, o: MutOrigin
    ](
        mut self, aad: Span[UInt8, aad_o], data: Span[UInt8, o]
    ) raises -> InlineArray[UInt8, TAG_SIZE]:
        """
        Encrypt `data` in place and return the 16-byte tag.

        Unlike GCM, the tag is computed *first*: POLYVAL absorbs `aad` and the
        plaintext, the result is combined with the nonce and encrypted to form
        the synthetic tag, and that tag (with its top bit cleared) seeds the CTR
        keystream used to encrypt `data`.
        """
        Self._assert_tag_size[TAG_SIZE]()
        raise Error("GcmSiv.encrypt: not implemented")

    def decrypt[
        TAG_SIZE: Int = Self.TAG_SIZE, aad_o: Origin, o: MutOrigin
    ](
        mut self,
        aad: Span[UInt8, aad_o],
        data: Span[UInt8, o],
        tag: InlineArray[UInt8, TAG_SIZE],
    ) raises:
        """
        Decrypt `data` in place, then verify `tag`.

        Because the tag seeds the CTR counter, GCM-SIV must decrypt before it can
        recompute the expected tag. The recomputed tag is compared against `tag`
        in constant time; on mismatch this raises and the now-decrypted `data` is
        zeroed (it cannot be left untouched the way `Gcm.decrypt` leaves it).
        """
        Self._assert_tag_size[TAG_SIZE]()
        raise Error("GcmSiv.decrypt: not implemented")

    def _derive_keys(
        self,
    ) raises -> Tuple[Self.G, InlineArray[UInt8, Self.Cipher.BLOCK_SIZE]]:
        """
        Derive the per-record POLYVAL key and message-encryption key.

        RFC 8452 §4: encrypt successive little-endian counter blocks (each the
        4-byte counter followed by the 12-byte nonce) under the key-generating
        key, taking the low 8 bytes of each output. Blocks 0-1 form the 16-byte
        message-authentication (POLYVAL) key; the remaining blocks form the
        message-encryption key (16 bytes for AES-128, 32 for AES-256).

        Returns the keyed POLYVAL instance and the message-encryption key bytes.
        Note: a fully generic implementation must construct a fresh `Cipher` from
        the derived message-encryption key, which requires keyed construction not
        yet exposed by the block-cipher traits — a constraint to resolve when
        implementing this.
        """
        raise Error("GcmSiv._derive_keys: not implemented")

    def _polyval_tag[
        aad_o: Origin, data_o: Origin
    ](
        self,
        var polyval: Self.G,
        aad: Span[UInt8, aad_o],
        data: Span[UInt8, data_o],
    ) raises -> InlineArray[UInt8, Self.TAG_SIZE]:
        """
        Compute the synthetic tag over `aad` and the *plaintext* `data`.

        POLYVAL absorbs `aad` and `data` (each zero-padded to a block), then a
        final block holding their bit-lengths. The result is XORed with the
        nonce, its top bit is cleared, and it is encrypted under the
        message-encryption key to yield the tag.
        """
        raise Error("GcmSiv._polyval_tag: not implemented")
