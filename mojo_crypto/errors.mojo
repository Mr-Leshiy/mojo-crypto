@fieldwise_init
struct GpuContextError(ImplicitlyDestructible, Writable):
    def write_to(self, mut writer: Some[Writer]):
        writer.write(
            "GPU context not initialized; construct Aes with a"
            " DeviceContext to use GPU methods"
        )
