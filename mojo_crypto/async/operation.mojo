from .context import Context

trait GpuOp:
    def __call__(ctx: Context) raises:
        pass