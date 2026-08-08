from max.gpu.host import DeviceContext
from std.gpu import global_idx
from std.sys import has_accelerator

from mojo_crypto.runtime.context import Context
from mojo_crypto.runtime.executor import Executor


# One thread per element: squares every value of the array in place.
# The size is a parameter, not an argument: `Int` is not `DevicePassable`, so
# it cannot cross the host/device boundary as a kernel argument.
def _double[SIZE: Int](data: Pointer[Scalar[DType.uint32], MutAnyOrigin]):
    var i = global_idx.x
    if i < SIZE:
        data[unsafe_offset=i] = data[unsafe_offset=i] * data[unsafe_offset=i]


# The coroutine reaches the GPU only through its `Context`, and reports back by
# mutating `data`: `Executor.add` drops the coroutine's result.
#
# It handles its own errors rather than being `raises`. The executor supplies no
# error slot, so a coroutine that actually raises takes the process down.
async def foo[N: Int](context: Context, mut data: Array[UInt32, N]):
    try:
        var gpu = context.gpu_ctx()

        var buf = gpu.enqueue_create_buffer[DType.uint32](N)
        buf.enqueue_copy_from(data)
        print("Start sync input")
        await context.yield_now()
        print("End sync input")

        comptime kernel = _double[N]
        gpu.enqueue_function[kernel](buf, grid_dim=1, block_dim=N)

        buf.enqueue_copy_to(data)
        print("Start sync output")
        await context.yield_now()
        print("End sync output")
    except e:
        print("foo failed:", e)


def main() raises:
    with DeviceContext() as ctx:
        var executor = Executor(ctx^)
        var context = executor.context()

        var a: Array[UInt32, 6] = [1, 2, 3, 4, 5, 6]
        var foo_c = foo(context, a)
        # Queued, not started: `wait` is what runs the body.
        executor.add(foo_c^)

        executor.wait()
