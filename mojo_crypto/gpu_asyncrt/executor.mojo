"""The queue that runs the coroutines and the device context they share."""

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
    """Runs coroutines that share one GPU device context.

    Tasks are queued by `add` and only make progress inside `wait`, which
    resumes them in turn until every one of them has completed.
    """

    var _inner: ArcPointer[_ExecutorInner]

    def __init__(out self, ctx: DeviceContext):
        """Initialize an executor running its tasks on the given device.

        Args:
            ctx: The device context shared by every task on this executor.
        """
        self._inner = ArcPointer(_ExecutorInner(ctx))

    def context(self) -> Context:
        """Return a context that coroutines use to reach this executor."""
        return Context(self._inner.copy())

    def add[
        type: Deinitable & Movable, origins: OriginSet
    ](
        mut self,
        var handle: Coroutine[type, origins],
        out task: Task[type, origins],
    ):
        """Queue a coroutine and return the task tracking it.

        The coroutine is not started here: `wait` is what runs it.

        Args:
            handle: The coroutine to run. Ownership is transferred.
        """
        task = Task(handle^, self._inner.copy())
        self._inner[].add(task._handle)

    def wait(self) raises:
        """Run queued tasks until all have completed, then sync the device."""
        self._inner[].wait()


struct _ExecutorInner:
    """The executor state shared between the `Executor` and its `Context`s."""

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
        """Initialize the shared state with an empty queue.

        Args:
            ctx: The device context shared by every task on this executor.
        """
        self._ctx = ctx
        self._q = OwnedPointer(Deque[AnyCoroutine]())

    def __deinit__(deinit self):
        """Destroy every coroutine still queued."""
        try:
            while len(self._q[]) > 0:
                var handle = self._q[].popleft()
                _coro_destroy_fn(handle)
        except:
            pass

    def add(mut self, handle: AnyCoroutine):
        """Queue a freshly created coroutine.

        Args:
            handle: The coroutine to run. The caller keeps ownership of it.
        """
        self.enqueue(handle)

    def enqueue(mut self, handle: AnyCoroutine):
        """Queue a suspended coroutine for a later resume.

        Args:
            handle: The coroutine to resume. The caller keeps ownership of it.
        """
        self._q[].append(handle)

    def wait(mut self) raises:
        """Run queued coroutines until all have completed."""

        @parameter
        def never() -> Bool:
            return False

        self.wait_until[never]()

    def wait_until[predicate: def() capturing thin -> Bool](mut self) raises:
        """Run queued coroutines until `predicate` holds or the queue empties.

        The device is synchronized before returning either way.
        """
        while not predicate() and len(self._q[]) > 0:
            var handle = self._q[].popleft()
            _coro_resume_fn(handle)

        self._ctx.synchronize()
