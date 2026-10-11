trait BlockCipherEncryptable:
    comptime BLOCK_SIZE: Int

    def encrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        ...


trait BlockCipherDecryptable:
    comptime BLOCK_SIZE: Int

    def decrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        ...
