from std.atomic import Atomic
from std.builtin.coroutine import AnyCoroutine
from std.memory import ArcPointer

from .executor import _ExecutorInner

comptime _COMPLETED_FLAG_TYPE = UInt8
comptime _CompletedFlagPointer = Pointer[
    Atomic[_COMPLETED_FLAG_TYPE], MutUntrackedOrigin
]


struct _TaskContext(TrivialRegisterPassable):
    comptime callback_fn_type = def(_CompletedFlagPointer) thin -> None

    var callback: Self.callback_fn_type
    var completed: _CompletedFlagPointer


def _mark_completed(flag: _CompletedFlagPointer):
    flag[].store(1)


struct Task[type: Deinitable, origins: OriginSet](Movable where False):
    var _executor: ArcPointer[_ExecutorInner]
    var _handle: AnyCoroutine
    var _completed: Atomic[_COMPLETED_FLAG_TYPE]
    var _result: Self.type

    def __init__(
        out self,
        var handle: Coroutine[Self.type, Self.origins],
        var executor: ArcPointer[_ExecutorInner],
    ):
        self._executor = executor^
        self._completed = Atomic[_COMPLETED_FLAG_TYPE](0)
        __mlir_op.`lit.ownership.mark_initialized`(
            __get_mvalue_as_litref(self._result)
        )
        handle._set_result_slot(Pointer(to=self._result))

        var ctx = handle._get_ctx[_TaskContext]()
        ctx[].callback = _mark_completed
        ctx[].completed = _CompletedFlagPointer(
            unsafe_from_address=Int(Pointer(to=self._completed))
        )

        self._handle = handle^._take_handle()

    def is_completed(self) -> Bool:
        return self._completed.load() != 0
