from mojo_crypto.block_ciphers.traits import BlockCipher


struct CtrMode[Cipher: BlockCipher & Movable & ImplicitlyDestructible](
    BlockCipher, ImplicitlyDestructible
):
    comptime BLOCK_SIZE: Int = Self.Cipher.BLOCK_SIZE

    var _cipher: Self.Cipher
    var _nonce: InlineArray[UInt8, 12]
    var _counter: UInt32

    def __init__(
        out self,
        var cipher: Self.Cipher,
        nonce: InlineArray[UInt8, 12],
        initial_counter: UInt32 = 0,
    ):
        self._cipher = cipher^
        self._nonce = nonce
        self._counter = initial_counter

    def encrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        var num_full_blocks = len(data) // Self.BLOCK_SIZE

        for i in range(num_full_blocks):
            var keystream = _counter_block(self._nonce, self._counter)
            self._cipher.encrypt(keystream)
            var offset = i * Self.BLOCK_SIZE
            for j in range(Self.BLOCK_SIZE):
                data[offset + j] ^= keystream[j]
            self._counter += 1

        var remaining = len(data) % Self.BLOCK_SIZE
        if remaining > 0:
            var keystream = _counter_block(self._nonce, self._counter)
            self._cipher.encrypt(keystream)
            var offset = num_full_blocks * Self.BLOCK_SIZE
            for j in range(remaining):
                data[offset + j] ^= keystream[j]
            self._counter += 1

    def decrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        self.encrypt(data)


def _counter_block(
    nonce: InlineArray[UInt8, 12], counter: UInt32
) -> InlineArray[UInt8, 16]:
    var block = InlineArray[UInt8, 16](fill=0)
    for i in range(12):
        block[i] = nonce[i]
    block[12] = UInt8(counter >> 24)
    block[13] = UInt8(counter >> 16)
    block[14] = UInt8(counter >> 8)
    block[15] = UInt8(counter)
    return block^
