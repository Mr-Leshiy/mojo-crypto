@fieldwise_init
struct BlockSizeError[Size: Int](Deinitable, Writable):
    """Raised when the input size is not a multiple of `Size`."""

    var size: Int

    @staticmethod
    def check(size: Int) raises BlockSizeError[Self.Size]:
        """Raise if `size` is not a multiple of `Size`."""
        if size % Self.Size != 0:
            raise BlockSizeError[Self.Size](size)

    def write_to(self, mut writer: Some[Writer]):
        writer.write(
            "input size must be a multiple of {}; got {}".format(
                Self.Size, self.size
            )
        )
