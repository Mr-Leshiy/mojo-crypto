from std.builtin.coroutine import AnyCoroutine, _coro_destroy_fn

from .executor import Executor


struct Task[type: Deinitable, origins: OriginSet, executor_origin: ImmOrigin](
    Movable where False
):
    var _executor: Pointer[Executor, Self.executor_origin]
    var _handle: AnyCoroutine
    var _result: Self.type

    def __init__(
        out self,
        var handle: Coroutine[Self.type, Self.origins],
        ref[Self.executor_origin] executor: Executor,
    ):
        self._executor = Pointer(to=executor)
        __mlir_op.`lit.ownership.mark_initialized`(
            __get_mvalue_as_litref(self._result)
        )
        handle._set_result_slot(Pointer(to=self._result))
        self._handle = handle^._take_handle()
