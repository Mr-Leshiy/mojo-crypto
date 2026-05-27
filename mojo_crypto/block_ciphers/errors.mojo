@fieldwise_init
struct BlockSizeError[Size: Int](ImplicitlyDestructible, Writable):
    var size: Int

    @staticmethod
    def check(size: Int) raises BlockSizeError[Self.Size]:
        if size % Self.Size != 0:
            raise BlockSizeError[Self.Size](size)

    def write_to(self, mut writer: Some[Writer]):
        writer.write(
            "input size must be a multiple of {}; got {}".format(
                Self.Size, self.size
            )
        )
