trait BlockCipher:
    comptime BLOCK_SIZE: Int

    def encrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        ...

    def decrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        ...
