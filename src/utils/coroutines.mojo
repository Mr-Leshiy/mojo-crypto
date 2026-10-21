"""Helpers for writing coroutines that run on a warp `Runtime`."""

from std.builtin._coroutine import AnyCoroutine, _suspend_async
from warp import Context


# Workaround for a compiler crash: a coroutine that is awaited by another
# coroutine and can return or raise before its first suspend point segfaults
# the compiler (https://github.com/modular/modular/issues/7361). Such a coroutine
# should first await `yield_now`, and be marked `@no_inline`, which the
# workaround also needs at the default optimization level. Awaiting an empty
# coroutine is not enough: it never suspends, so it hits the same crash.
# TODO: remove after https://github.com/modular/modular/issues/7361 would be
# resolved.
__async def yield_now(ctx: Context):
    """Suspend and re-queue the calling task, without syncing the device."""

    def body(hdl: AnyCoroutine) {ctx}:
        ctx._runtime[].requeue_current(hdl)

    _suspend_async(body)
