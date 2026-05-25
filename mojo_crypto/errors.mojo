@fieldwise_init
struct GpuContextError(ImplicitlyDestructible, Writable):
    def write_to(self, mut writer: Some[Writer]):
        writer.write(
            "GPU context not initialized; construct Aes with a"
            " DeviceContext to use GPU methods"
        )


@fieldwise_init
struct BlockSizeError(ImplicitlyDestructible, Writable):
    var size: Int

    def write_to(self, mut writer: Some[Writer]):
        writer.write(
            "input size must be a multiple of 16 (BLOCK_SIZE); got ", self.size
        )
