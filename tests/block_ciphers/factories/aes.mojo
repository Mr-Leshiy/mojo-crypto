from max.gpu.host import DeviceContext
from warp import Runtime

from mojo_crypto.block_ciphers.aes import (
    AesNaive,
    AesAarch64,
    AesX86,
    AesGpu,
)

from tests.block_ciphers.utils import BlockCipherEngine, BlockOn


trait AesFactory(Deinitable, Movable):
    """Creates the AES ciphers of one backend and key size, so that a check
    can be written once and run against every backend."""

    comptime KEY_SIZE: Int
    comptime Cipher: BlockCipherEngine

    def create(self, key: Array[UInt8, Self.KEY_SIZE]) raises -> Self.Cipher:
        ...


@fieldwise_init
struct AesNaiveFactory[KeySize: Int](AesFactory):
    comptime KEY_SIZE: Int = Self.KeySize
    comptime Cipher = AesNaive[Self.KeySize]

    def create(self, key: Array[UInt8, Self.KEY_SIZE]) raises -> Self.Cipher:
        return Self.Cipher(key)


@fieldwise_init
struct AesAarch64Factory[KeySize: Int](AesFactory):
    comptime KEY_SIZE: Int = Self.KeySize
    comptime Cipher = AesAarch64[Self.KeySize]

    def create(self, key: Array[UInt8, Self.KEY_SIZE]) raises -> Self.Cipher:
        return Self.Cipher(key)


@fieldwise_init
struct AesX86Factory[KeySize: Int](AesFactory):
    comptime KEY_SIZE: Int = Self.KeySize
    comptime Cipher = AesX86[Self.KeySize]

    def create(self, key: Array[UInt8, Self.KEY_SIZE]) raises -> Self.Cipher:
        return Self.Cipher(key)


struct AesGpuFactory[KeySize: Int](AesFactory):
    """Creates GPU ciphers on the given device, each wrapped in `BlockOn` so
    that the sync checks can run against it."""

    comptime KEY_SIZE: Int = Self.KeySize
    comptime Cipher = BlockOn[AesGpu[Self.KeySize]]

    var _runtime: Runtime

    def __init__(out self, ctx: DeviceContext):
        self._runtime = Runtime(ctx)

    def create(self, key: Array[UInt8, Self.KEY_SIZE]) raises -> Self.Cipher:
        var runtime = self._runtime.copy()
        var cipher = runtime.block_on(
            AesGpu[Self.KeySize].create(runtime.context(), key)
        )
        return BlockOn(runtime, cipher^)
