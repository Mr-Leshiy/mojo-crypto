"""Tasks: the queued coroutines, their results, and their completion flags."""

from std.atomic import Atomic
from std.builtin.coroutine import AnyCoroutine
from std.memory import ArcPointer

from .executor import _ExecutorInner

comptime _COMPLETED_FLAG_TYPE = UInt8
"""Flag type of the completion flag: `Atomic` cannot store a `Bool`'s `i1`."""

comptime _CompletedFlagPointer = Pointer[
    Atomic[_COMPLETED_FLAG_TYPE], MutUntrackedOrigin
]
"""Pointer to a task's completion flag, as the coroutine frame holds it."""


struct _TaskContext(TrivialRegisterPassable):
    """The completion callback installed in a task coroutine's frame.

    Replaces the stdlib's `_CoroutineContext` in the same slot, so it has to
    keep that shape: a thin callback followed by the pointer-sized payload the
    coroutine passes to it when it completes.
    """

    comptime callback_fn_type = def(_CompletedFlagPointer) thin -> None

    var callback: Self.callback_fn_type
    var completed: _CompletedFlagPointer


def _mark_completed(flag: _CompletedFlagPointer):
    """Raise a task's completion flag.

    Args:
        flag: The flag of the task whose coroutine has just completed.
    """
    flag[].store(1)


struct Task[type: Deinitable & Movable, origins: OriginSet](
    Movable where False
):
    """A coroutine queued on an `Executor`, and the result it will produce.

    Immovable: the coroutine writes its result and completion flag through
    pointers into this struct.
    """

    var _executor: ArcPointer[_ExecutorInner]
    var _handle: AnyCoroutine
    var _completed: Atomic[_COMPLETED_FLAG_TYPE]
    var _result: Self.type

    def __init__(
        out self,
        var handle: Coroutine[Self.type, Self.origins],
        var executor: ArcPointer[_ExecutorInner],
    ):
        """Initialize a task with a coroutine.

        Takes ownership of the provided coroutine and points it at this task's
        result slot and completion flag.

        Args:
            handle: The coroutine to execute as a task. Ownership is
                transferred.
            executor: The executor running the coroutine. Ownership is
                transferred.
        """
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

    def wait(deinit self) raises -> Self.type:
        """Run the executor until this task completes, then take its result.

        Consumes the task: the flag and the result slot it owns die with it.
        """

        @parameter
        def completed() -> Bool:
            return self.is_completed()

        self._executor[].wait_until[completed]()
        return self._result^

    def is_completed(self) -> Bool:
        """Return True once the coroutine has run to completion.

        A task that has not started, or that is parked on an `await`, reads as
        False; once True, the result is there.
        """
        return self._completed.load() != 0
