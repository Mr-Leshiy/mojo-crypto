"""A single-threaded async runtime for coroutines that drive a GPU.

An `Executor` owns a `DeviceContext` and runs the `Task`s added to it; a
coroutine reaches the device through a `Context` and suspends with `await` to
let the others make progress.
"""

from .executor import Executor
from .task import Task
from .context import Context
