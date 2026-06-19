from std.bit import byte_swap
from std.memory import memcpy

from mojo_crypto.aead.traits import AeadDecryptable, AeadEncryptable
from mojo_crypto.aead.errors import AuthenticationError
from mojo_crypto.block_ciphers.traits import (
    BlockCipherDecryptable,
    BlockCipherEncryptable,
)
from mojo_crypto.block_ciphers.modes import CtrMode
from mojo_crypto.universal_hashes.traits import UniversalHashable


struct Gcm[
    Cipher: BlockCipherEncryptable
    & BlockCipherDecryptable
    & Copyable
    & Movable
    & ImplicitlyDestructible,
    G: UniversalHashable & Copyable & Movable & ImplicitlyDestructible,
    NONCE_SIZE: Int,
](
    AeadDecryptable,
    AeadEncryptable,
    Copyable,
    ImplicitlyDestructible,
    Movable,
):
    """
    Galois/Counter Mode (GCM) authenticated encryption.

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
        Self._assert_valid_params()

        ghash_key = InlineArray[UInt8, Self.G.KEY_SIZE](fill=0)

        cipher.encrypt(ghash_key)

        self._ghash = Self.G(ghash_key)
        self._cipher = cipher^
        self._nonce = nonce

    @staticmethod
    def _assert_valid_params():
        comptime assert (
            Self.BLOCK_SIZE == 16
        ), "GCM is defined only for 128-bit (16-byte) block ciphers"
        comptime assert Self.NONCE_SIZE > 0, "GCM NONCE_SIZE must be positive"
        comptime assert (
            Self.G.BLOCK_SIZE == Self.BLOCK_SIZE
            and Self.G.TAG_SIZE == Self.BLOCK_SIZE
        ), "GCM requires a GHASH whose block/tag size match the cipher block"

    @staticmethod
    def _assert_tag_size[TAG_SIZE: Int]():
        comptime assert (
            TAG_SIZE > 0 and TAG_SIZE <= Self.BLOCK_SIZE
        ), "GCM TAG_SIZE must be between 1 and 16 bytes"

    def encrypt[
        TAG_SIZE: Int, aad_o: Origin, o: MutOrigin
    ](
        mut self, aad: Span[UInt8, aad_o], data: Span[UInt8, o]
    ) raises -> InlineArray[UInt8, TAG_SIZE]:
        """
        Encrypt `data` in place and return the `TAG_SIZE`-byte tag.

        The counter starts at inc32(J0); GHASH then authenticates `aad` together
        with the freshly produced ciphertext.
        """
        
        Self._assert_tag_size[TAG_SIZE]()

        var keystream = self._init_ctr()

        keystream[0].encrypt(data)

        return self._compute_tag[TAG_SIZE](keystream[1], aad, data)
        

    def decrypt[
        TAG_SIZE: Int, aad_o: Origin, o: MutOrigin
    ](
        mut self,
        aad: Span[UInt8, aad_o],
        data: Span[UInt8, o],
        tag: InlineArray[UInt8, TAG_SIZE],
    ) raises:
        """
        Verify `tag`, then decrypt `data` in place.

        The tag is recomputed over `aad` and the input ciphertext and compared
        in constant time. On mismatch this raises and `data` is left untouched.

        `tag_size` satisfies the generic `Aead.decrypt` signature but is pinned
        to this instance's `TAG_SIZE`; it is inferred from `tag`.
        """

        Self._assert_tag_size[TAG_SIZE]()

        var keystream = self._init_ctr()

        # Authenticate the input ciphertext *before* decrypting so `data` is left
        # untouched if verification fails.
        var expected_tag = self._compute_tag[TAG_SIZE](keystream[1], aad, data)

        # Constant-time comparison: XOR all bytes at once and OR-reduce, so the
        # running time does not depend on where the first mismatch occurs.
        #
        # A short-circuiting `!=` would leak, via timing, how many leading bytes
        # matched. For a secret-vs-attacker-supplied tag that enables a forgery
        # attack:
        #   - Attacker submits a guessed tag, measures how long the reject takes.
        #   - Longer time => more leading bytes were correct.
        #   - Brute-force one byte at a time (256 tries each) instead of 2^128,
        #     making tag forgery feasible.
        #
        # alignment=1 because the InlineArray[UInt8] bases may be unaligned.
        var e = expected_tag.unsafe_ptr().load[
            width=TAG_SIZE, alignment=1
        ]()
        var t = tag.unsafe_ptr().load[width=TAG_SIZE, alignment=1]()
        if (e ^ t).reduce_or() != 0:
            raise AuthenticationError()

        keystream[0].decrypt(data)

    def _init_ctr(
        self,
    ) raises -> Tuple[
        CtrMode[Self.Cipher], InlineArray[UInt8, Self.BLOCK_SIZE]
    ]:
        """
        Initialize counter mode.

        See algorithm described in Section 7.2 of NIST SP800-38D:
        <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf>

        > Define a block, J0, as follows:
        > If len(IV)=96, then J0 = IV || 0{31} || 1.
        > If len(IV) ≠ 96, then let s = 128 ⎡len(IV)/128⎤-len(IV), and
        >     J0=GHASH(IV||0s+64||[len(IV)]64).

        Returns the counter positioned at inc32(J0) (ready to encrypt data) and
        the tag mask E(J0), used to mask the final GHASH output.
        """

        Self._assert_valid_params()

        j0 = InlineArray[UInt8, Self.BLOCK_SIZE](fill=0)

        comptime if Self.NONCE_SIZE == 12:
            # J0 = IV || 0^31 || 1
            memcpy(
                dest=j0.unsafe_ptr(),
                src=self._nonce.unsafe_ptr(),
                count=Self.NONCE_SIZE,
            )
            j0[Self.BLOCK_SIZE - 1] = 1
        else:
            comptime BE_NONCE_BITS: UInt64 = byte_swap(
                UInt64(Self.NONCE_SIZE) * 8
            )

            # J0 = GHASH(IV || 0^(s+64) || [len(IV)]_64)
            var ghash = self._ghash.copy()
            ghash.update_padded(self._nonce)

            # Final block: 64 zero bits followed by the IV bit-length (big-endian).
            var length_block = InlineArray[UInt8, Self.G.BLOCK_SIZE](fill=0)
            # Write nonce_bits as 8 big-endian bytes into the last 8 bytes of the
            # block: byte_swap turns the native little-endian u64 into big-endian,
            # then store it as a u64 over those bytes. alignment=1 because the
            # InlineArray[UInt8] base is not guaranteed to be 8-byte aligned.
            (length_block.unsafe_ptr() + Self.G.BLOCK_SIZE - 8).bitcast[
                UInt64
            ]().store[alignment=1](BE_NONCE_BITS)
            ghash.update_block(length_block)

            j0 = rebind[InlineArray[UInt8, Self.BLOCK_SIZE]](ghash^.finalize())

        # CtrMode starts at J0; consuming the first keystream block yields the
        # tag mask E(J0) and advances the counter to inc32(J0) for the data.
        ctr = CtrMode[Self.Cipher](self._cipher.copy(), j0^)
        tag_mask = InlineArray[UInt8, Self.BLOCK_SIZE](fill=0)
        ctr.encrypt(tag_mask)

        return (ctr^, tag_mask)

    def _compute_tag[
        TAG_SIZE: Int,
        aad_o: Origin, data_o: Origin
    ](
        self,
        mask: InlineArray[UInt8, Self.BLOCK_SIZE],
        aad: Span[UInt8, aad_o],
        data: Span[UInt8, data_o],
    ) raises -> InlineArray[UInt8, TAG_SIZE]:
        """
        Authenticate the ciphertext `data` and associated data `aad`.

        GHASH absorbs `aad` and `data` (each zero-padded to a block boundary),
        then a final block holding their bit-lengths; the result is masked with
        `mask` (= E(J0)) and the leading TAG_SIZE bytes are returned (GCM permits
        a truncated tag).
        """

        Self._assert_valid_params()

        var ghash = self._ghash.copy()
        ghash.update_padded(aad)
        ghash.update_padded(data)

        # Final block: [len(aad)]_64 || [len(data)]_64, both big-endian bit
        # counts. byte_swap converts the native little-endian u64 to big-endian
        # before the store; alignment=1 because the InlineArray[UInt8] base may
        # be unaligned.
        var length_block = InlineArray[UInt8, Self.G.BLOCK_SIZE](fill=0)
        var aad_bits = UInt64(len(aad)) * 8
        var data_bits = UInt64(len(data)) * 8
        length_block.unsafe_ptr().bitcast[UInt64]().store[alignment=1](
            byte_swap(aad_bits)
        )
        (length_block.unsafe_ptr() + 8).bitcast[UInt64]().store[alignment=1](
            byte_swap(data_bits)
        )
        ghash.update_block(length_block)

        var full_tag = rebind[InlineArray[UInt8, Self.BLOCK_SIZE]](
            ghash^.finalize()
        )
        # full_tag ^= mask, one SIMD lane per byte. alignment=1 because the
        # InlineArray[UInt8] bases are not guaranteed to be 16-byte aligned.
        var t = full_tag.unsafe_ptr().load[width=Self.BLOCK_SIZE, alignment=1]()
        var m = mask.unsafe_ptr().load[width=Self.BLOCK_SIZE, alignment=1]()
        full_tag.unsafe_ptr().store[alignment=1](t ^ m)

        # GCM permits a truncated tag: return the leading TAG_SIZE bytes.
        var tag = InlineArray[UInt8, TAG_SIZE](uninitialized=True)
        memcpy(
            dest=tag.unsafe_ptr(),
            src=full_tag.unsafe_ptr(),
            count=TAG_SIZE,
        )
        return tag^
