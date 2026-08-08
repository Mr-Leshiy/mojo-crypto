from max.gpu.host import DeviceContext
from std.builtin.coroutine import (
    AnyCoroutine,
    _coro_resume_fn,
    _suspend_async,
)
from std.sys import has_accelerator
from std.collections import Deque
from std.ffi import _Global

from .task import Task

comptime _EXECUTOR = _Global["ASYNC_GPU_EXECUTOR", Executor, _init_executor]


struct Executor:
    var _ctx: DeviceContext
    var _q: Deque[AnyCoroutine]

    def __init__(out self, ctx: DeviceContext):
        self._ctx = ctx
        self._q = Deque[AnyCoroutine]()

    def gpu_ctx(self) -> DeviceContext:
        return self._ctx

    def wait(mut self) raises:
        while len(self._q) > 0:
            _coro_resume_fn(self._q.popleft())
        self._ctx.synchronize()

    async def yield_now(mut self):
        """Suspend the calling coroutine and put it back on the run queue.

        The only interleaving point: without a `yield_now`, a spawned coroutine
        runs start to finish before the next one begins.
        """

        @parameter
        def body(hdl: AnyCoroutine):
            self._q.append(hdl)

        _suspend_async[body]()
