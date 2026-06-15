@fieldwise_init
struct UhashSizeError[Size: Int](ImplicitlyDestructible, Writable):
    var size: Int

    @staticmethod
    def check(size: Int) raises UhashSizeError[Self.Size]:
        if size % Self.Size != 0:
            raise UhashSizeError[Self.Size](size)

    def write_to(self, mut writer: Some[Writer]):
        writer.write(
            "input size must be a multiple of {}; got {}".format(
                Self.Size, self.size
            )
        )
