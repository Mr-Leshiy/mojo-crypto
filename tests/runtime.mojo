from max.gpu.host import DeviceContext

from mojo_crypto.runtime.context import Context
from mojo_crypto.runtime.executor import Executor


async def foo(i: Int) -> Int:
    print("calling foo", i)
    return i + 1


def main() raises:
    with DeviceContext() as gpu_ctx:
        print("Init executor")
        var ctx = Context(gpu_ctx)
        var executor = Executor(ctx^)

        for i in range(3):
            executor.spawn(foo(i))
        executor.run()
        print("done")
