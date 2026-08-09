from max.gpu.host import DeviceContext
from std.builtin.coroutine import (
    AnyCoroutine,
    _coro_resume_fn,
    _coro_destroy_fn,
)
from std.collections import Deque
from std.memory import ArcPointer, OwnedPointer

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
    ](
        mut self,
        var handle: Coroutine[type, origins],
        out task: Task[type, origins],
    ):
        handle._set_noop_callback()
        task = Task(handle^, self._inner.copy())
        self._inner[].add(task._handle)

    def wait(self) raises:
        self._inner[].wait()


struct _ExecutorInner:
    var _ctx: DeviceContext

    # The queue has to stay behind a pointer. `wait` takes `mut self` — an
    # exclusive, `noalias` borrow — yet a coroutine it resumes reaches this
    # same object through the `Context`'s executor pointer to enqueue itself.
    # Stored inline, the deque header would sit in that exclusively borrowed
    # memory and may be cached in registers across the resume, silently
    # dropping the append. Behind a pointer the header lives outside that
    # borrow and both paths agree on it. Note that the queue is genuinely
    # shared-mutable across those two paths, so `OwnedPointer`'s uniqueness
    # claim is a fiction the optimizer is free to act on.
    # (Analysis by Claude)
    var _q: OwnedPointer[Deque[AnyCoroutine]]

    def __init__(out self, ctx: DeviceContext):
        self._ctx = ctx
        self._q = OwnedPointer(Deque[AnyCoroutine]())

    def __deinit__(deinit self):
        try:
            while len(self._q[]) > 0:
                var handle = self._q[].popleft()
                _coro_destroy_fn(handle)
        except:
            pass

    def add(mut self, handle: AnyCoroutine):
        self.enqueue(handle)

    def enqueue(mut self, handle: AnyCoroutine):
        self._q[].append(handle)

    def wait(mut self) raises:
        while len(self._q[]) > 0:
            var handle = self._q[].popleft()
            _coro_resume_fn(handle)
        self._ctx.synchronize()
