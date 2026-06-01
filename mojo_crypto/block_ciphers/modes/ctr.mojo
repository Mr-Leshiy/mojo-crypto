from mojo_crypto.block_ciphers.traits import BlockCipher


# https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
# Section 6.5
struct CtrMode[Cipher: BlockCipher & Movable & ImplicitlyDestructible](
    BlockCipher, ImplicitlyDestructible
):
    comptime BLOCK_SIZE: Int = Self.Cipher.BLOCK_SIZE

    var _cipher: Self.Cipher
    var _ctr: List[UInt8]

    def __init__(
        out self,
        var cipher: Self.Cipher,
        ctr: InlineArray[UInt8, Self.Cipher.BLOCK_SIZE],
    ):
        self._cipher = cipher^
        self._ctr = List[UInt8](capacity=Self.BLOCK_SIZE)
        for i in range(Self.BLOCK_SIZE):
            self._ctr.append(ctr[i])

    def encrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        self._apply(data)

    def decrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        self._apply(data)

    def _apply[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        var offset = 0
        while offset < len(data):
            var keystream = self._ctr.copy()
            self._cipher.encrypt(keystream[:])
            var end = offset + Self.BLOCK_SIZE
            if end > len(data):
                end = len(data)
            for j in range(end - offset):
                data[offset + j] ^= keystream[j]
            self._increment_ctr()
            offset += Self.BLOCK_SIZE

    def _increment_ctr(mut self):
        # inc128: full 128-bit big-endian increment (NIST SP 800-38A)
        for i in range(Self.BLOCK_SIZE - 1, -1, -1):
            self._ctr[i] += 1
            if self._ctr[i] != 0:
                break
