from max.gpu.host import DeviceContext
from std.sys import has_accelerator
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from mojo_crypto.gpu_asyncrt.context import Context
from mojo_crypto.gpu_asyncrt.executor import Executor


async def _yield_once(context: Context) -> Int:
    await context.synchronize()
    return 1


async def _yields_twice[VALUE: Int](context: Context) -> Int:
    var total = VALUE
    total += await _yield_once(context)
    total += await _yield_once(context)
    return total



def test_task_completes_with_its_result() raises:
    comptime if has_accelerator():
        with DeviceContext() as ctx:
            var executor = Executor(ctx)
            var context = executor.context()

            var task = executor.add(_yields_twice[5](context))
            assert_false(task.is_completed())

            executor.wait()

            assert_true(task.is_completed())
            # 5 plus one from each of the two nested coroutines it awaited.
            assert_equal(task._result, 7)


def test_tasks_complete_independently() raises:
    comptime if has_accelerator():
        with DeviceContext() as ctx:
            var executor = Executor(ctx)
            var context = executor.context()

            var first = executor.add(_yields_twice[10](context))
            var second = executor.add(_yields_twice[20](context))

            executor.wait()

            # Both ran to completion even though each parked twice on the way,
            # i.e. the queue really did round-robin between them.
            assert_true(first.is_completed())
            assert_true(second.is_completed())
            assert_equal(first._result, 12)
            assert_equal(second._result, 22)


def test_wait_without_tasks_leaves_executor_usable() raises:
    comptime if has_accelerator():
        with DeviceContext() as ctx:
            var executor = Executor(ctx)
            var context = executor.context()

            # Nothing queued: this has to return rather than wedge the queue.
            executor.wait()

            var task = executor.add(_yields_twice[0](context))
            executor.wait()

            assert_true(task.is_completed())
            assert_equal(task._result, 2)

            # A second drain of an already-empty queue changes nothing.
            executor.wait()
            assert_true(task.is_completed())


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
