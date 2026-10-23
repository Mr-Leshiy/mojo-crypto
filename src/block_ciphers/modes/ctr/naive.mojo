from ....utils import load_bytes, to_bytes
from ...traits import (
    BlockCipherDecryptable,
    BlockCipherEncryptable,
)
from .common import _check_params, _increment_ctr, _xor_keystream


struct CtrMode[
    C: BlockCipherEncryptable & BlockCipherDecryptable & Movable & Deinitable,
    SIZE: Int = C.BLOCK_SIZE,
    BIG_ENDIAN: Bool = True,
](
    BlockCipherDecryptable,
    BlockCipherEncryptable,
    Deinitable,
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

    var _cipher: Self.C
    var _ctr: SIMD[DType.uint8, Self.BLOCK_SIZE]

    def __init__(
        out self,
        var cipher: Self.C,
        var ctr: Array[UInt8, Self.BLOCK_SIZE],
    ):
        """Initialize from a fully-assembled initial counter block."""

        _check_params[Self.BLOCK_SIZE, Self.SIZE]()

        self._cipher = cipher^
        self._ctr = load_bytes[dtype=DType.uint8, width=Self.BLOCK_SIZE](ctr)

    def encrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        self._apply(data)

    def decrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        self._apply(data)

    def _apply[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        var offset = 0
        while offset < len(data):
            # The keystream block is E(counter). The cipher works on bytes, so
            # the counter goes out as an array.
            var keystream = to_bytes[
                input_size=Self.BLOCK_SIZE, output_size=Self.BLOCK_SIZE
            ](self._ctr)
            self._cipher.encrypt(keystream)

            var end = min(offset + Self.BLOCK_SIZE, len(data))
            _xor_keystream[Self.BLOCK_SIZE](data[offset:end], Span(keystream))

            _increment_ctr[Self.SIZE, Self.BIG_ENDIAN](self._ctr)
            offset += Self.BLOCK_SIZE
