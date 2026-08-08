from max.gpu.host import DeviceContext
from std.gpu import global_idx
from std.runtime.asyncrt import create_raising_task

from mojo_crypto.runtime.executor import Executor


# One thread per element: doubles every value of the array in place.
# The size is a parameter, not an argument: `Int` is not `DevicePassable`, so
# it cannot cross the host/device boundary as a kernel argument.
def _double[SIZE: Int](data: Pointer[Scalar[DType.uint32], MutAnyOrigin]):
    var i = global_idx.x
    if i < SIZE:
        data[unsafe_offset=i] = data[unsafe_offset=i] * data[unsafe_offset=i]


async def foo[
    N: Int
](mut executor: Executor, data: Array[UInt32, N]) raises -> Array[UInt32, N]:
    var ctx = executor.gpu_ctx()

    var result = data.copy()

    var buf = ctx.enqueue_create_buffer[DType.uint32](N)
    buf.enqueue_copy_from(result)
    print("Start sync input")
    await executor.yield_now()
    print("End sync input")

    comptime kernel = _double[N]
    ctx.enqueue_function[kernel](buf, grid_dim=1, block_dim=N)

    buf.enqueue_copy_to(result)
    print("Start sync output")
    await executor.yield_now()
    print("End sync output")

    return result^


def main() raises:
    with DeviceContext() as ctx:
        var executor = Executor(ctx^)

        var a: Array[UInt32, 6] = [1, 2, 3, 4, 5, 6]
        var foo_c = foo(executor, a)
        var task = create_raising_task(foo_c^)

        try:
            executor.wait()
        except e:
            print("Error: ", e)

        print(task^.wait())
