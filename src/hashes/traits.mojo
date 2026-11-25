from max.gpu.host import DeviceBuffer
from std.sys.info import CompilationTarget
from warp import Context


trait Digest:
    """A hash function with fixed-length output."""

    comptime BLOCK_SIZE: Int
    """Size of the compression function's input block, in bytes."""

    comptime OUTPUT_SIZE: Int
    """
    Size of the digest `finalize` returns, in bytes.
    """

    def __init__(out self):
        """Initialize the hash to its initial state."""
        ...

    def update[o: Origin](mut self, data: Span[UInt8, o]):
        """Absorb more input."""
        ...

    def finalize(var self) -> Array[UInt8, Self.OUTPUT_SIZE]:
        """Consume self and return the OUTPUT_SIZE-byte digest."""
        ...

    def reset(mut self):
        """Reset the hash to its initial state."""
        ...


trait Xof:
    """An extendable-output function: a hash with arbitrary-length output."""

    comptime BLOCK_SIZE: Int
    """Size of the sponge's absorption block (its rate), in bytes."""

    def __init__(out self):
        """Initialize to the initial state."""
        ...

    def update[o: Origin](mut self, data: Span[UInt8, o]):
        """Absorb more input. Must not be called once `squeeze` has been."""
        ...

    def squeeze[size: Int](mut self) -> Array[UInt8, size]:
        """Return the next `size` bytes of output."""
        var out = Array[UInt8, size](fill=0)
        self.squeeze(out)
        return out^

    def squeeze[o: MutOrigin](mut self, data: Span[UInt8, o]):
        """Fill `data` with the next `len(data)` bytes of output.

        The first call ends the absorbing phase; `update` may not be called
        after. Repeated calls continue squeezing where the previous one left
        off, so the output is independent of how it is chunked.
        """
        ...

    def reset(mut self):
        """Reset to the initial state."""
        ...


trait GpuDigest:
    """A hash function with fixed-length output, run on a GPU over a batch of
    independent messages.

    A single message is hashed sequentially, so the GPU parallelism comes from
    the batch: implementations hash each message in its own GPU thread.

    Batch layout: the input holds N messages of the same `message_size` bytes,
    back to back, message `i` at `[i * message_size, (i + 1) * message_size)`.
    The output receives the N digests back to back, digest `i` at
    `[i * OUTPUT_SIZE, (i + 1) * OUTPUT_SIZE)`. N is taken from the output:
    `N = len(output) // OUTPUT_SIZE`, so a batch of empty messages
    (`message_size == 0`) is well defined. An empty output is an empty batch.

    Size contract, checked before any work is enqueued: `message_size >= 0`,
    `len(output)` is a multiple of `OUTPUT_SIZE`, and
    `len(input) == N * message_size`, i.e. the input length is a multiple of the
    message size and the output holds exactly N * `OUTPUT_SIZE` bytes. A
    violation raises `BatchSizeError` and leaves `output` untouched.

    Each call is independent: a batch is hashed from scratch, and there is no
    incremental `update` across calls. Methods take `self` immutably; an
    instance only holds what does not depend on the input, such as round
    constants already uploaded to the device.
    """

    comptime BLOCK_SIZE: Int
    """Size of the compression function's input block, in bytes."""

    comptime OUTPUT_SIZE: Int
    """Size of each message's digest, in bytes."""

    __async def hash_batch[
        target: CompilationTarget, i: Origin, o: MutOrigin
    ](
        self,
        ctx: Context[target],
        input: Span[UInt8, i],
        output: Span[UInt8, o],
        message_size: Int,
    ) raises:
        """Hash the batch in host `input` into host `output`, returning once
        fully synchronized.

        See the trait docs for the layout and the size contract.
        """
        ...

    def hash_batch[
        target: CompilationTarget
    ](
        self,
        ctx: Context[target],
        input: DeviceBuffer[DType.uint8],
        output: DeviceBuffer[DType.uint8],
        message_size: Int,
    ) raises:
        """Enqueue hashing of the batch in device `input` into device `output`.

        Synchronizing `ctx` is the caller's responsibility; `input` and
        `output` must not be touched until it is synchronized. See the trait
        docs for the layout and the size contract.
        """
        ...


trait GpuXof:
    """An extendable-output function run on a GPU over a batch of independent
    messages, each squeezed to the same caller-chosen output length.

    Batch layout: the input holds N messages of the same `message_size` bytes,
    back to back, message `i` at `[i * message_size, (i + 1) * message_size)`.
    The output receives N outputs of the same `output_size` bytes, back to back,
    output `i` at `[i * output_size, (i + 1) * output_size)`. N is taken from
    the output: `N = len(output) // output_size`, so a batch of empty messages
    (`message_size == 0`) is well defined. An empty output is an empty batch.

    Size contract, checked before any work is enqueued: `message_size >= 0`,
    `output_size > 0`, `len(output)` is a multiple of `output_size`, and
    `len(input) == N * message_size`. A violation raises `BatchSizeError` and
    leaves `output` untouched.

    One-shot only: each call absorbs every message and squeezes its first
    `output_size` bytes. Squeezing more of the same messages in a later call is
    not supported; ask for the full length up front instead (output `i` of a
    longer request starts with output `i` of a shorter one).
    Methods take `self` immutably, as in `GpuDigest`.
    """

    comptime BLOCK_SIZE: Int
    """Size of the sponge's absorption block (its rate), in bytes."""

    __async def hash_batch[
        target: CompilationTarget, i: Origin, o: MutOrigin
    ](
        self,
        ctx: Context[target],
        input: Span[UInt8, i],
        output: Span[UInt8, o],
        message_size: Int,
        output_size: Int,
    ) raises:
        """Hash the batch in host `input` into host `output`, returning once
        fully synchronized.

        See the trait docs for the layout and the size contract.
        """
        ...

    def hash_batch[
        target: CompilationTarget
    ](
        self,
        ctx: Context[target],
        input: DeviceBuffer[DType.uint8],
        output: DeviceBuffer[DType.uint8],
        message_size: Int,
        output_size: Int,
    ) raises:
        """Enqueue hashing of the batch in device `input` into device `output`.

        Synchronizing `ctx` is the caller's responsibility; `input` and
        `output` must not be touched until it is synchronized. See the trait
        docs for the layout and the size contract.
        """
        ...
