from mojo_crypto.block_ciphers.traits import (
    BlockCipherDecryptable,
    BlockCipherEncryptable,
)


struct CtrMode[
    C: BlockCipherEncryptable
    & BlockCipherDecryptable
    & Movable
    & ImplicitlyDestructible,
    SIZE: Int = C.BLOCK_SIZE,
    BIG_ENDIAN: Bool = True,
](
    BlockCipherDecryptable,
    BlockCipherEncryptable,
    ImplicitlyDestructible,
    Movable,
):
    """
    Counter (CTR) block cipher mode.

    NIST SP 800-38A, Section 6.5:
    https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

    `SIZE` is the width in bytes of the incrementing counter field; the
    remaining `BLOCK_SIZE - SIZE` bytes are the fixed nonce, never touched by
    the increment. `SIZE == BLOCK_SIZE` (the default) increments the whole block.

    `BIG_ENDIAN` (default) places the counter in the last `SIZE` bytes and
    increments big-endian (CTR-32BE / AES-GCM style). When `False`, the counter
    occupies the first `SIZE` bytes and increments little-endian (CTR-32LE).
    """

    comptime BLOCK_SIZE: Int = Self.C.BLOCK_SIZE
    comptime NONCE_SIZE: Int = Self.BLOCK_SIZE - Self.SIZE

    var _cipher: Self.C
    var _ctr: InlineArray[UInt8, Self.C.BLOCK_SIZE]

    @staticmethod
    def _assert_valid_params():
        comptime assert Self.SIZE > 0, "counter SIZE must be positive"
        comptime assert (
            Self.SIZE <= Self.BLOCK_SIZE
        ), "counter SIZE cannot exceed BLOCK_SIZE"

    def __init__(
        out self,
        var cipher: Self.C,
        ctr: InlineArray[UInt8, Self.BLOCK_SIZE],
    ):
        """Initialize from a fully-assembled initial counter block."""

        Self._assert_valid_params()

        self._cipher = cipher^
        self._ctr = ctr

    def encrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        self._apply(data)

    def decrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        self._apply(data)

    def _apply[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        var offset = 0
        while offset < len(data):
            var keystream = self._ctr
            var ks = Span[UInt8, origin_of(keystream)](
                ptr=keystream.unsafe_ptr(), length=Self.BLOCK_SIZE
            )
            self._cipher.encrypt(ks)
            var end = min(offset + Self.BLOCK_SIZE, len(data))
            for j in range(end - offset):
                data[offset + j] ^= keystream[j]
            self._increment_ctr()
            offset += Self.BLOCK_SIZE

    def _increment_ctr(mut self):
        # Increment is confined to the SIZE-byte counter field; the nonce bytes
        # are never carried into (NIST SP 800-38A).
        comptime if Self.BIG_ENDIAN:
            # counter = last SIZE bytes, big-endian
            for i in range(Self.BLOCK_SIZE - 1, Self.NONCE_SIZE - 1, -1):
                self._ctr[i] += 1
                if self._ctr[i] != 0:
                    break
        else:
            # counter = first SIZE bytes, little-endian
            for i in range(Self.SIZE):
                self._ctr[i] += 1
                if self._ctr[i] != 0:
                    break
