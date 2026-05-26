from std.gpu.host import DeviceContext, DeviceBuffer

from ..common import SBOX, SBOX_INV


struct AesGpuBackend(ImplicitlyDestructible, Movable):
    var ctx: DeviceContext
    var w: DeviceBuffer[DType.uint32]
    var sbox: DeviceBuffer[DType.uint32]
    var sbox_inv: DeviceBuffer[DType.uint8]

    def __init__[
        WordsSize: Int
    ](out self, ctx: DeviceContext, w: InlineArray[UInt32, WordsSize]) raises:
        self.ctx = ctx
        self.w = ctx.enqueue_create_buffer[DType.uint32](WordsSize)
        self.w.enqueue_copy_from(w)

        self.sbox = ctx.enqueue_create_buffer[DType.uint32](256)
        self.sbox.enqueue_copy_from(SBOX.unsafe_ptr())

        self.sbox_inv = ctx.enqueue_create_buffer[DType.uint8](256)
        self.sbox_inv.enqueue_copy_from(SBOX_INV.unsafe_ptr())
