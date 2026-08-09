from max.gpu.host import DeviceContext
from std.builtin.coroutine import (
    AnyCoroutine,
    _coro_resume_fn,
    _coro_destroy_fn
)
from std.collections import Deque
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

    var _q: ArcPointer[Deque[AnyCoroutine]]

    def __init__(out self, ctx: DeviceContext):
        self._ctx = ctx
        self._q = ArcPointer(Deque[AnyCoroutine]())

    def __deinit__(deinit self):
        try:
            while len(self._q[]) > 0:
                var hdl = self._q[].popleft()
                _coro_destroy_fn(hdl)
        except:
            pass

    def add[
        type: Deinitable, origins: OriginSet
    ](mut self, var hdl: Coroutine[type, origins]):
        hdl._set_noop_callback()
        self.enqueue(hdl^._take_handle())

    def enqueue(mut self, hdl: AnyCoroutine):
        self._q[].append(hdl)

    def wait(mut self) raises:
        while len(self._q[]) > 0:
            var hdl = self._q[].popleft()
            _coro_resume_fn(hdl)
        self._ctx.synchronize()
