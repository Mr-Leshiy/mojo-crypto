from std.atomic import Atomic
from std.runtime.asyncrt import _TaskGroupBox

from .context import Context


struct Executor:
    var ctx: Context

    var counter: Atomic[DType.int]
    var tasks: List[_TaskGroupBox]

    def __init__(out self, var ctx: Context):
        self.ctx = ctx^
        self.counter = Atomic[DType.int](1)
        self.tasks = List[_TaskGroupBox](capacity=16)


    def spawn(mut self, var handle: Coroutine[...], out task: Task[handle.type, handle.origins]):
        task = Task(handle^)
       

    def run(mut self) raises:
        """Wait for every spawned coroutine, then wait for the device once."""
        self.tg.wait()
        self.ctx.device_ctx.synchronize()
