comptime HEX_CHARS: StaticString = "0123456789abcdef"


@fieldwise_init
struct HexError(ImplicitlyDestructible, Writable):
    var message: String

    def write_to(self, mut writer: Some[Writer]):
        writer.write(self.message)
