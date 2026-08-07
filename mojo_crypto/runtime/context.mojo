from max.gpu.host import DeviceContext


struct Context(Copyable, Movable):
    var device_ctx: DeviceContext

    def __init__(out self, var device_ctx: DeviceContext):
        self.device_ctx = device_ctx^
