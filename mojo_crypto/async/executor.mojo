from .context import Context
from std.gpu.host import DeviceContext


struct Executor:
    var ctx: Context
    var tasks: List[]


    def __init__(out self, ctx: Context):
        self.ctx = ctx

