from std.math import ceildiv, round
from std.sys import has_accelerator
from std.gpu import block_dim, block_idx, thread_idx
from std.gpu.host import DeviceContext
from std.memory import UnsafePointer
from std.reflection import reflect
from std.testing import assert_equal
from std.time import perf_counter_ns
from std.utils import Variant

comptime BLOCK_DIM = 256
comptime Size = 256 * 8


def _heavy_kernel(
    data: UnsafePointer[UInt8, MutAnyOrigin],
    size: Int,
):
    comptime ITERS = 50_000

    var i = block_idx.x * block_dim.x + thread_idx.x
    if i < size:
        var v = data[i] * data[i]
        for _ in range(ITERS):
            v = v * v + UInt8(1)
            v = v ^ (v >> 3)
            v = v * UInt8(31) + UInt8(7)
        data[i] = v


def _light_kernel(
    data: UnsafePointer[UInt8, MutAnyOrigin],
    size: Int,
):
    comptime ITERS = 100

    var i = block_idx.x * block_dim.x + thread_idx.x
    if i < size:
        var v = data[i] + data[i]
        for _ in range(ITERS):
            v = v + v + UInt8(3)
            v = v ^ (v << 2)
            v = v * UInt8(17) + UInt8(5)
        data[i] = v


# Derive per-op input data from `index`, so no two ops feed the GPU the same
# bytes. Done host-side, before the data is handed to the kernel.
def seed_input(
    input: InlineArray[UInt8, Size], index: Int
) -> InlineArray[UInt8, Size]:
    var seeded = InlineArray[UInt8, Size](uninitialized=True)
    for i in range(Size):
        seeded[i] = input[i] ^ UInt8(index)
    return seeded^


# A GPU op is any of the kernels above (`_heavy_kernel`, `_light_kernel`, ...),
# wrapped in a thin functor so it has a concrete, reflectable, storable type
# — Mojo's `def(...) -> ...` function types can't be stored in a `List`
# directly, only used as parameter-position bounds.
trait GpuOp(Copyable, Movable):
    def __call__(
        self, ctx: DeviceContext, input: InlineArray[UInt8, Size]
    ) raises -> InlineArray[UInt8, Size]:
        ...


@fieldwise_init
struct HeavyOp(GpuOp):
    var index: Int

    def __call__(
        self, ctx: DeviceContext, input: InlineArray[UInt8, Size]
    ) raises -> InlineArray[UInt8, Size]:
        var seeded = seed_input(input, self.index)

        var buf = ctx.enqueue_create_buffer[DType.uint8](Size)
        buf.enqueue_copy_from(seeded.unsafe_ptr())

        ctx.enqueue_function[_heavy_kernel](
            buf,
            Size,
            grid_dim=ceildiv(Size, BLOCK_DIM),
            block_dim=BLOCK_DIM,
        )

        var output = InlineArray[UInt8, Size](uninitialized=True)
        buf.enqueue_copy_to(output.unsafe_ptr())
        return output^


@fieldwise_init
struct LightOp(GpuOp):
    var index: Int

    def __call__(
        self, ctx: DeviceContext, input: InlineArray[UInt8, Size]
    ) raises -> InlineArray[UInt8, Size]:
        var seeded = seed_input(input, self.index)

        var buf = ctx.enqueue_create_buffer[DType.uint8](Size)
        buf.enqueue_copy_from(seeded.unsafe_ptr())

        ctx.enqueue_function[_light_kernel](
            buf,
            Size,
            grid_dim=ceildiv(Size, BLOCK_DIM),
            block_dim=BLOCK_DIM,
        )

        var output = InlineArray[UInt8, Size](uninitialized=True)
        buf.enqueue_copy_to(output.unsafe_ptr())
        return output^


# Closed set of GpuOp implementers a Sequential/Parallel can be given. Add
# new op structs here (and to the Variant) to make them selectable from main().
comptime GpuOpVariant = Variant[HeavyOp, LightOp]


def call_gpu_op(
    op: GpuOpVariant, ctx: DeviceContext, input: InlineArray[UInt8, Size]
) raises -> InlineArray[UInt8, Size]:
    if op.isa[HeavyOp]():
        return op[HeavyOp](ctx, input)
    return op[LightOp](ctx, input)


trait AsyncGpuDemo:
    def __call__(
        self, ctx: DeviceContext, input: InlineArray[UInt8, Size]
    ) raises -> None:
        ...


@fieldwise_init
struct Sequential(AsyncGpuDemo, Copyable, Movable):
    var ops: List[GpuOpVariant]

    def __call__(
        self, ctx: DeviceContext, input: InlineArray[UInt8, Size]
    ) raises -> None:
        for op in self.ops:
            _ = call_gpu_op(op, ctx, input)
            ctx.synchronize()


@fieldwise_init
struct Parallel(AsyncGpuDemo, Copyable, Movable):
    var ops: List[GpuOpVariant]

    def __call__(
        self, ctx: DeviceContext, input: InlineArray[UInt8, Size]
    ) raises -> None:
        for op in self.ops:
            _ = call_gpu_op(op, ctx, input)
        ctx.synchronize()


# Generic timing wrapper: reflects on `O`'s type to print its name, so any
# `AsyncGpuDemo` implementer gets timed/labeled without passing a name.
# Returns the elapsed time in ms so callers can compare runs.
def timed[
    O: AsyncGpuDemo
](op: O, ctx: DeviceContext, input: InlineArray[UInt8, Size]) raises -> Float64:
    var start = perf_counter_ns()
    op(ctx, input)
    var end = perf_counter_ns()
    var elapsed_ms = Float64(end - start) / 1_000_000.0

    print(reflect[O].name())
    print("elapsed:", elapsed_ms, "ms")
    print("-------")
    return elapsed_ms


def compare(
    label: StaticString,
    ctx: DeviceContext,
    input: InlineArray[UInt8, Size],
    ops: List[GpuOpVariant],
) raises:
    print("===", label, "===")

    var sequential_ms = timed(Sequential(ops=ops.copy()), ctx, input)
    var parallel_ms = timed(Parallel(ops=ops.copy()), ctx, input)

    var diff_ms = round((sequential_ms - parallel_ms) * 100) / 100
    var diff_pct = round((diff_ms / sequential_ms) * 100.0 * 100) / 100
    print("difference:", diff_ms, "ms")

    if diff_ms > 0:
        print("parallel is:", diff_pct, "% faster")
    else:
        print("sequential is:", -1 * diff_pct, "% faster")
    print()


def main() raises:
    comptime if not has_accelerator():
        print("No GPU found; skipping async_gpu demo")
    else:
        with DeviceContext() as ctx:
            comptime OPS_NUMBER: Int = 100

            var input = InlineArray[UInt8, Size](uninitialized=True)
            for i in range(Size):
                input[i] = UInt8(i)

            var light_first = List[GpuOpVariant]()
            for i in range(OPS_NUMBER):
                light_first.append(LightOp(i))
            for i in range(OPS_NUMBER):
                light_first.append(HeavyOp(i))
            compare("light first", ctx, input, light_first)

            var heavy_first = List[GpuOpVariant]()
            for i in range(OPS_NUMBER):
                heavy_first.append(HeavyOp(i))
            for i in range(OPS_NUMBER):
                heavy_first.append(LightOp(i))
            compare("heavy first", ctx, input, heavy_first)
