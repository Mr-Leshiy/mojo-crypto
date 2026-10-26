from max.gpu.host import DeviceContext
from warp import Runtime

from mojo_crypto.block_ciphers.aes import AesGpu
from mojo_crypto.block_ciphers.modes import CtrMode, GpuCtrMode

from tests.block_ciphers.factories.aes import AesFactory
from tests.block_ciphers.utils import BlockCipherModeEngine, BlockOn


trait CtrFactory:
    """Creates the CTR modes of one backend, key size and counter layout, so
    that a check can be written once and run against every backend."""

    comptime KEY_SIZE: Int
    comptime BLOCK_SIZE: Int
    comptime Mode: BlockCipherModeEngine

    def create(
        self,
        key: Array[UInt8, Self.KEY_SIZE],
        var ctr: Array[UInt8, Self.BLOCK_SIZE],
    ) raises -> Self.Mode:
        ...


@fieldwise_init
struct CtrModeFactory[
    F: AesFactory,
    //,
    SIZE: Int = F.Cipher.BLOCK_SIZE,
    BIG_ENDIAN: Bool = True,
](CtrFactory):
    """Creates `CtrMode`s over the ciphers of a sync AES backend."""

    comptime KEY_SIZE: Int = Self.F.KEY_SIZE
    comptime BLOCK_SIZE: Int = Self.F.Cipher.BLOCK_SIZE
    comptime Mode = CtrMode[Self.F.Cipher, Self.SIZE, Self.BIG_ENDIAN]

    var _aes: Self.F

    def create(
        self,
        key: Array[UInt8, Self.KEY_SIZE],
        var ctr: Array[UInt8, Self.BLOCK_SIZE],
    ) raises -> Self.Mode:
        return Self.Mode(self._aes.create(key), ctr^)


struct GpuCtrModeFactory[
    KeySize: Int,
    SIZE: Int = AesGpu[KeySize].BLOCK_SIZE,
    BIG_ENDIAN: Bool = True,
](CtrFactory):
    """Creates `GpuCtrMode`s on the given device, each wrapped in `BlockOn` so
    that the sync checks can run against it."""

    comptime KEY_SIZE: Int = Self.KeySize
    comptime BLOCK_SIZE: Int = AesGpu[Self.KeySize].BLOCK_SIZE
    comptime Engine = GpuCtrMode[
        AesGpu[Self.KeySize], Self.SIZE, Self.BIG_ENDIAN
    ]
    comptime Mode = BlockOn[Self.Engine]

    var _runtime: Runtime

    def __init__(out self, ctx: DeviceContext):
        self._runtime = Runtime(ctx)

    def create(
        self,
        key: Array[UInt8, Self.KEY_SIZE],
        var ctr: Array[UInt8, Self.BLOCK_SIZE],
    ) raises -> Self.Mode:
        var runtime = self._runtime.copy()
        var cipher = runtime.block_on(
            AesGpu[Self.KeySize].create(runtime.context(), key)
        )
        return BlockOn(runtime, Self.Engine(cipher^, ctr^))
