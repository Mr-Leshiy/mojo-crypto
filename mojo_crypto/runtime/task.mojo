from std.builtin.coroutine import AnyCoroutine
from std.memory import ArcPointer

from .executor import _ExecutorInner


struct Task[type: Deinitable, origins: OriginSet](Movable where False):
    var _executor: ArcPointer[_ExecutorInner]
    var _handle: AnyCoroutine
    var _result: Self.type

    def __init__(
        out self,
        var handle: Coroutine[Self.type, Self.origins],
        var executor: ArcPointer[_ExecutorInner],
    ):
        self._executor = executor^
        __mlir_op.`lit.ownership.mark_initialized`(
            __get_mvalue_as_litref(self._result)
        )
        handle._set_result_slot(Pointer(to=self._result))
        self._handle = handle^._take_handle()
