from max.gpu.host import DeviceContext
from std.builtin.coroutine import (
    AnyCoroutine,
    RaisingCoroutine,
    _CoroutineContext,
    _coro_resume_fn,
    _coro_resume_noop_callback,
)
from std.sys import has_accelerator
from std.collections import Deque
from std.ffi import _Global
from std.memory import ArcPointer

from .context import Context
from .task import Task

struct Executor(Movable):
    var _inner: ArcPointer[_ExecutorInner]

    def __init__(out self, ctx: DeviceContext):
        self._inner = ArcPointer(_ExecutorInner(ctx))

    def context(self) -> Context:
        return Context(self._inner.copy())

    def add[
        type: Deinitable, origins: OriginSet
    ](self, var handle: Coroutine[type, origins]):
        self._inner[].add(handle^)

    def wait(self) raises:
        self._inner[].wait()


struct _ExecutorInner:
    var _ctx: DeviceContext
    var _q: Deque[AnyCoroutine]

    def __init__(out self, ctx: DeviceContext):
        self._ctx = ctx
        self._q = Deque[AnyCoroutine]()

    def add[
        type: Deinitable, origins: OriginSet
    ](mut self, var handle: Coroutine[type, origins]):
        handle._set_noop_callback()
        self.enqueue(handle^._take_handle())

    def enqueue(mut self, hdl: AnyCoroutine):
        self._q.append(hdl)

    def wait(mut self) raises:
        while len(self._q) > 0:
            print("Before resume", len(self._q))
            _coro_resume_fn(self._q.popleft())
            print("After resume", len(self._q))
        print("Wait finished")
        self._ctx.synchronize()