from max.gpu.host import DeviceContext
from std.builtin.coroutine import (
    AnyCoroutine,
    _coro_resume_fn,
    _suspend_async,
)
from std.collections import Deque
from std.memory import ArcPointer

from .executor import _ExecutorInner


struct Context(Movable):
    var _executor: ArcPointer[_ExecutorInner]

    def __init__(out self, var executor: ArcPointer[_ExecutorInner]):
        self._executor = executor^

    def gpu_ctx(self) -> DeviceContext:
        return self._executor[]._ctx

    async def yield_now(self):
        @parameter
        def body(hdl: AnyCoroutine):
            self._executor[].enqueue(hdl)
            print("yield now", len(self._executor[]._q))

        _suspend_async[body]()
