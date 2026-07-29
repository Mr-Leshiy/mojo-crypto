from std.math import ceildiv
from std.sys import has_accelerator
from std.gpu import block_dim, block_idx, thread_idx
from std.gpu.host import DeviceContext
from std.memory import UnsafePointer
from std.testing import assert_equal

comptime BLOCK_DIM = 256


# Elementwise data[i] *= data[i]
def _square_kernel(
    data: UnsafePointer[UInt8, MutAnyOrigin],
    size: Int,
):
    var i = block_idx.x * block_dim.x + thread_idx.x
    if i < size:
        data[i] = data[i] * data[i]


# Elementwise data[i] += data[i]
def _double_kernel(
    data: UnsafePointer[UInt8, MutAnyOrigin],
    size: Int,
):
    var i = block_idx.x * block_dim.x + thread_idx.x
    if i < size:
        data[i] = data[i] + data[i]


def square_gpu[
    Size: Int
](ctx: DeviceContext, input: InlineArray[UInt8, Size]) raises -> InlineArray[
    UInt8, Size
]:
    var buf = ctx.enqueue_create_buffer[DType.uint8](Size)
    buf.enqueue_copy_from(input.unsafe_ptr())

    ctx.enqueue_function[_square_kernel, _square_kernel](
        buf,
        Size,
        grid_dim=ceildiv(Size, BLOCK_DIM),
        block_dim=BLOCK_DIM,
    )
    ctx.synchronize()

    var output = InlineArray[UInt8, Size](uninitialized=True)
    buf.enqueue_copy_to(output.unsafe_ptr())
    ctx.synchronize()
    return output^


def double_gpu[
    Size: Int
](ctx: DeviceContext, input: InlineArray[UInt8, Size]) raises -> InlineArray[
    UInt8, Size
]:
    var buf = ctx.enqueue_create_buffer[DType.uint8](Size)
    buf.enqueue_copy_from(input.unsafe_ptr())

    ctx.enqueue_function[_double_kernel, _double_kernel](
        buf,
        Size,
        grid_dim=ceildiv(Size, BLOCK_DIM),
        block_dim=BLOCK_DIM,
    )
    ctx.synchronize()

    var output = InlineArray[UInt8, Size](uninitialized=True)
    buf.enqueue_copy_to(output.unsafe_ptr())
    ctx.synchronize()
    return output^


def main() raises:
    comptime if not has_accelerator():
        print("No GPU found; skipping async_gpu demo")
    else:
        with DeviceContext() as ctx:
            comptime Size = 8
            var input = InlineArray[UInt8, Size](uninitialized=True)
            for i in range(Size):
                input[i] = UInt8(i)

            var squared = square_gpu[Size](ctx, input)
            var doubled = double_gpu[Size](ctx, input)

            for i in range(Size):
                assert_equal(squared[i], UInt8(i) * UInt8(i))
                assert_equal(doubled[i], UInt8(i) + UInt8(i))

            print("square_gpu/double_gpu verified for", Size, "elements")
