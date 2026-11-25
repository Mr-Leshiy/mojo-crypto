@fieldwise_init
struct BatchSizeError(Deinitable, Writable):
    """Raised when the buffers of a GPU batch hash call do not describe a
    batch of equal-length messages.

    See `GpuDigest.hash_batch` and `GpuXof.hash_batch` for the contract.
    """

    var input_size: Int
    """Size of the input buffer, in bytes."""

    var output_size: Int
    """Size of the output buffer, in bytes."""

    var message_size: Int
    """Requested size of each message, in bytes."""

    var digest_size: Int
    """Requested size of each message's output, in bytes."""

    @staticmethod
    def check(
        input_size: Int, output_size: Int, message_size: Int, digest_size: Int
    ) raises BatchSizeError:
        """Raise unless `message_size >= 0`, `digest_size > 0`, `output_size`
        is a multiple of `digest_size`, and `input_size` is exactly
        `(output_size // digest_size) * message_size`.
        """
        if (
            message_size < 0
            or digest_size <= 0
            or output_size % digest_size != 0
            or input_size != (output_size // digest_size) * message_size
        ):
            raise BatchSizeError(
                input_size, output_size, message_size, digest_size
            )

    def write_to(self, mut writer: Some[Writer]):
        writer.write(
            (
                "a batch of N messages of {} bytes each with {} bytes of"
                " output each needs an input of N * {} bytes and an output"
                " of N * {} bytes; got {} input and {} output bytes"
            ).format(
                self.message_size,
                self.digest_size,
                self.message_size,
                self.digest_size,
                self.input_size,
                self.output_size,
            )
        )
