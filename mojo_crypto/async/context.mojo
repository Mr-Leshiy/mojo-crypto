
from std.gpu.host import DeviceContext

struct Context:
    var device_ctx: DeviceContext

    def __init__(out self, device_ctx: DeviceContext):
        self.device_ctx = device_ctx