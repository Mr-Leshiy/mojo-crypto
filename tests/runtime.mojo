from max.gpu.host import DeviceContext
from std.time import monotonic
from std.runtime.asyncrt import create_task

from mojo_crypto.runtime.executor import Executor


async def foo(mut executor: Executor) -> Int:
    return await timeout(executor, 50)

async def foo1() -> Int:
    return 1 + 1


async def timeout(mut executor: Executor, ms: Int) -> Int:
    var deadline = monotonic() + ms * 1_000_000
    var polls = 0
    while monotonic() < deadline:
        polls += 1
        # await executor.yield_now()
    print("timeout", ms, "ms elapsed after", polls, "polls")
    return polls


def main() raises:
    with DeviceContext() as ctx:
        var executor = Executor()

        var task = create_task(foo(executor))

        print("Done, polls:", task.wait())
