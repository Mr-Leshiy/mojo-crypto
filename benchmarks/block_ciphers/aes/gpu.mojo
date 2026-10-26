from max.gpu.host import DeviceContext
from warp import Runtime

from mojo_crypto.block_ciphers.aes import AesGpu
from mojo_crypto.block_ciphers.modes import GpuCbcMode, GpuCtrMode

from benchmarks.block_ciphers.aes.common import MODE, bench_engine
from tests.block_ciphers.utils import BlockOn


# `BlockOn` runs each call to completion with `runtime.block_on`, so this
# measures a single call's latency, not throughput across concurrent tasks.
def bench_cipher[
    KeySize: Int, prefix: StringLiteral
](mut runtime: Runtime) raises:
    comptime C = AesGpu[KeySize]

    var key = Array[UInt8, KeySize](fill=0)
    var iv = Array[UInt8, C.BLOCK_SIZE](fill=0)
    var cipher = runtime.block_on(C.create(runtime.context(), key))
    var name = String(prefix, "_", MODE)

    comptime if MODE == "ecb":
        bench_engine(BlockOn(runtime, cipher^), name)
    elif MODE == "cbc":
        bench_engine(BlockOn(runtime, GpuCbcMode[C](cipher^, iv^)), name)
    elif MODE == "ctr":
        bench_engine(BlockOn(runtime, GpuCtrMode[C](cipher^, iv^)), name)
    else:
        comptime assert False, "MODE must be one of: ecb, cbc, ctr"


def main() raises:
    print("Running AES GPU benchmarks")

    with DeviceContext() as ctx:
        var runtime = Runtime(ctx)
        bench_cipher[16, "aes128"](runtime)
        bench_cipher[24, "aes192"](runtime)
        bench_cipher[32, "aes256"](runtime)
