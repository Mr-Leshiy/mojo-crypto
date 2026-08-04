@fieldwise_init
struct AuthenticationError(Deinitable, Writable):
    """Raised when AEAD tag verification fails during decryption."""

    def write_to(self, mut writer: Some[Writer]):
        writer.write("AEAD authentication failed")
