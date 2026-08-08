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

    # The run queue lives behind its own shared pointer, and no method below
    # takes `mut self`. Both halves matter.
    #
    # A resumed coroutine reaches this very queue through the `Context`'s copy
    # of the executor pointer, so `wait` must not hold an exclusive borrow
    # across `_coro_resume_fn`: under `mut self` the compiler may keep the
    # `Deque` header in registers for the duration of the resume and write it
    # back afterwards, silently discarding whatever `yield_now` enqueued. Going
    # through the pointer instead keeps both paths on the same header.
    var _q: ArcPointer[Deque[AnyCoroutine]]

    def __init__(out self, ctx: DeviceContext):
        self._ctx = ctx
        self._q = ArcPointer(Deque[AnyCoroutine]())

    def add[
        type: Deinitable, origins: OriginSet
    ](self, var handle: Coroutine[type, origins]):
        handle._set_noop_callback()
        self.enqueue(handle^._take_handle())

    def enqueue(self, hdl: AnyCoroutine):
        self._q[].append(hdl)

    def wait(self) raises:
        while len(self._q[]) > 0:
            # Pop first, resume second: the handle has to leave the queue
            # before the coroutine can push itself back on.
            var hdl = self._q[].popleft()
            _coro_resume_fn(hdl)
        self._ctx.synchronize()
