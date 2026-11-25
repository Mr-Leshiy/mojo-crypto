"""Compile-only checks that the GPU hash traits are well-formed, plus the
`BatchSizeError` size contract they document. The GPU backends that implement
the traits are tested on their own."""

from max.gpu.host import DeviceBuffer
from std.sys.info import CompilationTarget
from std.testing import TestSuite, assert_raises
from warp import Context

from mojo_crypto.hashes import BatchSizeError, GpuDigest, GpuXof


struct _DummyGpuDigest(Deinitable, GpuDigest, Movable):
    """Conforms to `GpuDigest` without hashing anything."""

    comptime BLOCK_SIZE: Int = 64
    comptime OUTPUT_SIZE: Int = 32

    __async def hash_batch[
        target: CompilationTarget, i: Origin, o: MutOrigin
    ](
        self,
        ctx: Context[target],
        input: Span[UInt8, i],
        output: Span[UInt8, o],
        message_size: Int,
    ) raises:
        BatchSizeError.check(
            len(input), len(output), message_size, Self.OUTPUT_SIZE
        )

    def hash_batch[
        target: CompilationTarget
    ](
        self,
        ctx: Context[target],
        input: DeviceBuffer[DType.uint8],
        output: DeviceBuffer[DType.uint8],
        message_size: Int,
    ) raises:
        BatchSizeError.check(
            len(input), len(output), message_size, Self.OUTPUT_SIZE
        )


struct _DummyGpuXof(Deinitable, GpuXof, Movable):
    """Conforms to `GpuXof` without hashing anything."""

    comptime BLOCK_SIZE: Int = 168

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
        BatchSizeError.check(len(input), len(output), message_size, output_size)

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
        BatchSizeError.check(len(input), len(output), message_size, output_size)


def _conforms[T: GpuDigest]():
    ...


def _conforms_xof[T: GpuXof]():
    ...


def test_dummies_conform() raises:
    _conforms[_DummyGpuDigest]()
    _conforms_xof[_DummyGpuXof]()


def test_batch_size_accepts() raises:
    # 3 messages of 5 bytes, 32 bytes of output each.
    BatchSizeError.check(15, 96, 5, 32)
    # Empty messages: N comes from the output.
    BatchSizeError.check(0, 64, 0, 32)
    # Empty batch.
    BatchSizeError.check(0, 0, 5, 32)


def test_batch_size_rejects() raises:
    # Input not N * message_size.
    with assert_raises(contains="got 14 input and 96 output bytes"):
        BatchSizeError.check(14, 96, 5, 32)
    # Output not a multiple of the per-message output size.
    with assert_raises():
        BatchSizeError.check(15, 95, 5, 32)
    # Negative message size.
    with assert_raises():
        BatchSizeError.check(0, 0, -1, 32)
    # Zero per-message output size.
    with assert_raises():
        BatchSizeError.check(0, 0, 5, 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
