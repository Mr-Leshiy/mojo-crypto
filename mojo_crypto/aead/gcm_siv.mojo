from std.bit import byte_swap
from std.memory import memcpy
from std.sys.info import is_little_endian

from mojo_crypto.aead.traits import AeadDecryptable, AeadEncryptable
from mojo_crypto.aead.errors import AuthenticationError
from mojo_crypto.block_ciphers.traits import (
    BlockCipherDecryptable,
    BlockCipherEncryptable,
)
from mojo_crypto.block_ciphers.modes import CtrMode
from mojo_crypto.universal_hashes.traits import UniversalHashable


@fieldwise_init
struct LengthError(ImplicitlyDestructible, Writable):
    """Raised when GCM-SIV input exceeds the maximum permitted length."""

    var aad_len: Int
    var data_len: Int

    def write_to(self, mut writer: Some[Writer]):
        writer.write(
            "GCM-SIV input exceeds the maximum permitted length (aad={},"
            " data={})".format(self.aad_len, self.data_len)
        )


@fieldwise_init
struct GcmSiv[
    C: BlockCipherEncryptable
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

    comptime BLOCK_SIZE: Int = Self.C.BLOCK_SIZE
    comptime NONCE_SIZE: Int = 12
    comptime TAG_SIZE: Int = 16

    # Maximum length of associated data (RFC 8452 § 6).
    comptime A_MAX: UInt64 = 1 << 36
    # Maximum length of plaintext (RFC 8452 § 6).
    comptime P_MAX: UInt64 = 1 << 36
    # Maximum length of ciphertext (RFC 8452 § 6).
    comptime C_MAX: UInt64 = (1 << 36) + 16

    # The message-encryption cipher, keyed with the per-record message-encryption
    # key derived in `create`. Used for both CTR encryption and tag encryption.
    var _cipher: Self.C
    var _polyval: Self.G
    var _nonce: InlineArray[UInt8, Self.NONCE_SIZE]

    @staticmethod
    def create[
        KEY_SIZE: Int,
        cipher_init: def(InlineArray[UInt8, KEY_SIZE]) raises capturing[
            _
        ] -> Self.C,
    ](
        key_generating_key: InlineArray[UInt8, KEY_SIZE],
        nonce: InlineArray[UInt8, Self.NONCE_SIZE],
    ) raises -> Self:
        """Initialize GCM-SIV with the key-generating-key cipher and nonce."""
        Self._assert_valid_params()

        # The key-generating-key cipher is used only to derive the subkeys.
        var cipher = cipher_init(key_generating_key)

        # A single counter sequence runs across both keys: 0,1 for the POLYVAL
        # key, then 2,3 (AES-128) or 2..5 (AES-256) for the message-encryption
        # key. `_derive_subkey` takes the *starting* counter, so the second call
        # resumes where the first left off (G.KEY_SIZE // 8 blocks of 8 bytes).
        var mac_key = _derive_subkey[N=Self.G.KEY_SIZE](
            cipher,
            0,
            nonce,
        )
        var enc_key = _derive_subkey[N=KEY_SIZE](
            cipher,
            UInt32(Self.G.KEY_SIZE // 8),
            nonce,
        )

        # POLYVAL is keyed with mac_key; `_cipher` is keyed with enc_key.
        return Self(cipher_init(enc_key), Self.G(mac_key), nonce)

    @staticmethod
    def _assert_valid_params():
        comptime assert Self.BLOCK_SIZE == 16 or Self.BLOCK_SIZE == 32, (
            "GCM-SIV is defined only for 128-bit (16-byte) or 256-bit (32-byte)"
            " block ciphers"
        )
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
        TAG_SIZE: Int, aad_o: Origin, o: MutOrigin
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

        # RFC 8452 § 6 caps the AAD and plaintext lengths.
        if UInt64(len(aad)) > Self.A_MAX or UInt64(len(data)) > Self.P_MAX:
            raise LengthError(len(aad), len(data))

        # POLYVAL absorbs the AAD then the plaintext, each zero-padded to a
        # block boundary.
        self._polyval.update_padded(aad)
        self._polyval.update_padded(data)

        # The synthetic tag is computed first, over AAD + plaintext.
        var tag = self._compute_tag(len(aad), len(data))

        # The tag seeds the CTR counter that encrypts the payload in place.
        var ctr = self._init_ctr(tag)
        ctr.encrypt(data)

        return rebind[InlineArray[UInt8, TAG_SIZE]](tag)

    def decrypt[
        TAG_SIZE: Int, aad_o: Origin, o: MutOrigin
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
        in constant time; on mismatch this raises and the recovered plaintext is
        re-encrypted back to the input ciphertext (it cannot be left untouched
        the way `Gcm.decrypt` leaves it), so a tampered `data` is never exposed.
        """
        Self._assert_tag_size[TAG_SIZE]()

        # RFC 8452 § 6 caps the AAD and ciphertext lengths.
        if UInt64(len(data)) > Self.C_MAX or UInt64(len(aad)) > Self.A_MAX:
            raise LengthError(len(aad), len(data))

        var tag_block = rebind[InlineArray[UInt8, Self.TAG_SIZE]](tag)

        # POLYVAL absorbs the AAD (padded) first.
        self._polyval.update_padded(aad)

        # The supplied tag seeds the CTR counter; applying the keystream
        # decrypts `data` in place (CTR is symmetric).
        var ctr = self._init_ctr(tag_block)
        ctr.encrypt(data)

        # `data` now holds the recovered plaintext; POLYVAL absorbs it (padded).
        self._polyval.update_padded(data)

        # Recompute the synthetic tag over AAD + recovered plaintext.
        var expected_tag = self._compute_tag(len(aad), len(data))

        # Constant-time comparison: XOR all bytes at once and OR-reduce so the
        # running time does not depend on where the first mismatch occurs (see
        # Gcm.decrypt for why a short-circuiting compare would leak). alignment=1
        # because the InlineArray[UInt8] bases may be unaligned.
        var e = expected_tag.unsafe_ptr().load[width=TAG_SIZE, alignment=1]()
        var t = tag.unsafe_ptr().load[width=TAG_SIZE, alignment=1]()
        if (e ^ t).reduce_or() != 0:
            # On verification failure, re-encrypt the recovered plaintext back to
            # the input ciphertext so the tampered plaintext is never exposed.
            var reenc = self._init_ctr(tag_block)
            reenc.encrypt(data)
            raise AuthenticationError()

    def _compute_tag(
        mut self,
        aad_len: Int,
        buffer_len: Int,
    ) raises -> InlineArray[UInt8, Self.TAG_SIZE]:
        """
        Finish the POLYVAL tag over already-absorbed AAD and payload.

        `self._polyval` is assumed to have already absorbed the (padded) AAD and
        plaintext blocks. This appends the final length block, finalizes, folds
        in the nonce, and encrypts the result under `enc_cipher` (the per-record
        message-encryption key) to produce the synthetic tag.

        RFC 8452 §4 (<https://tools.ietf.org/html/rfc8452#section-4>):
        """

        # Final POLYVAL block: AAD bit-length and payload bit-length as two
        # little-endian u64s. Unlike GHASH (big-endian), POLYVAL is
        # little-endian. Build both lengths as a 2-lane vector and store them at
        # once; byte_swap each lane on a big-endian host so the in-memory bytes
        # are little-endian regardless of host endianness (the branch is
        # resolved at compile time, so it costs nothing on little-endian
        # targets). alignment=1 because the InlineArray[UInt8] base may be
        # unaligned.
        var length_block = InlineArray[UInt8, Self.G.BLOCK_SIZE](fill=0)
        var lengths = SIMD[DType.uint64, 2](
            UInt64(aad_len) * 8, UInt64(buffer_len) * 8
        )

        comptime if not is_little_endian():
            lengths = byte_swap(lengths)

        length_block.unsafe_ptr().bitcast[UInt64]().store[alignment=1](lengths)

        self._polyval.update_block(length_block)
        var tag = rebind[InlineArray[UInt8, Self.TAG_SIZE]](
            self._polyval.copy().finalize()
        )
        # Reset the live accumulator (it still holds this message's AAD and
        # payload) so this instance can authenticate another message from
        # scratch (finalize-then-reset, per RFC 8452).
        self._polyval.reset()

        # XOR the nonce into the first 12 bytes of the tag.
        for i in range(Self.NONCE_SIZE):
            tag[i] ^= self._nonce[i]

        # Clear the most significant bit of the last byte.
        tag[Self.BLOCK_SIZE - 1] &= 0x7F

        # Encrypt the synthetic tag under the message-encryption key.
        self._cipher.encrypt(tag)

        return tag^

    def _init_ctr(
        self,
        nonce: InlineArray[UInt8, Self.TAG_SIZE],
    ) -> CtrMode[Self.C, 4, BIG_ENDIAN=False]:
        """
        Initialize counter mode for payload encryption/decryption.

        RFC 8452 § 4 (<https://tools.ietf.org/html/rfc8452#section-4>):

        > The initial counter block is the tag with the most significant bit of
        > the last byte set to one.
        """

        # counter_block = tag with the MSB of the last byte set to one.
        var counter_block = nonce.copy()
        counter_block[Self.BLOCK_SIZE - 1] |= 0x80
        return CtrMode[Self.C, 4, BIG_ENDIAN=False](
            self._cipher.copy(),
            rebind[InlineArray[UInt8, Self.BLOCK_SIZE]](counter_block),
        )


def _derive_subkey[
    C: BlockCipherEncryptable & ImplicitlyDestructible,
    N: Int,
    NONCE_SIZE: Int,
](
    mut cipher: C,
    var counter: UInt32,
    nonce: InlineArray[UInt8, NONCE_SIZE],
) raises -> InlineArray[UInt8, N]:
    """
    Derive subkeys from the master key-generating-key in counter mode.

    From RFC8452 § 4: <https://tools.ietf.org/html/rfc8452#section-4>

    > The message-authentication key is 128 bit, and the message-encryption
    > key is either 128 (for AES-128) or 256 bit (for AES-256).
    >
    > These keys are generated by encrypting a series of plaintext blocks
    > that contain a 32-bit, little-endian counter followed by the nonce,
    > and then discarding the second half of the resulting ciphertext.  In
    > the AES-128 case, 128 + 128 = 256 bits of key material need to be
    > generated, and, since encrypting each block yields 64 bits after
    > discarding half, four blocks need to be encrypted.  The counter
    > values for these blocks are 0, 1, 2, and 3.  For AES-256, six blocks
    > are needed in total, with counter values 0 through 5 (inclusive).

    `counter` is the starting counter value for this key; the caller passes the
    next value in the sequence for each successive key.
    """
    comptime assert (
        N % 8 == 0
    ), "GCM-SIV derived key size must be a multiple of 8 bytes"

    var key = InlineArray[UInt8, N](uninitialized=True)
    var block = InlineArray[UInt8, C.BLOCK_SIZE](fill=0)
    for chunk in range(N // 8):
        # block[0:4] = counter as a little-endian u32, host-independent: only
        # byte_swap on a big-endian host (branch resolved at compile time).
        var c = counter

        comptime if not is_little_endian():
            c = byte_swap(c)
        block.unsafe_ptr().bitcast[UInt32]().store[alignment=1](c)

        # block[4:16] = nonce.
        memcpy(
            dest=block.unsafe_ptr() + 4,
            src=nonce.unsafe_ptr(),
            count=NONCE_SIZE,
        )

        cipher.encrypt(block)

        # Keep the low 8 bytes, discard the rest.
        memcpy(
            dest=key.unsafe_ptr() + chunk * 8,
            src=block.unsafe_ptr(),
            count=8,
        )

        counter += 1

    return key^
