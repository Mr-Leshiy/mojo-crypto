from std.benchmark import run
from max.gpu.host import DeviceContext
from warp import Runtime

from mojo_crypto.block_ciphers.aes import (
    AesGpu,
    Aes128Gpu,
    Aes192Gpu,
    Aes256Gpu,
)

from benchmarks.block_ciphers.aes.common import (
    BLOCKS_4K,
    BLOCKS_8K,
    BLOCKS_16K,
)


# Each iteration runs one call to completion with `runtime.block_on`,
# so this measures a single call's latency, not throughput across concurrent
# tasks.
def bench_cipher[
    KeySize: Int, prefix: StringLiteral
](mut runtime: Runtime) raises:
    var key = Array[UInt8, KeySize](fill=0)
    var cipher = runtime.block_on(
        AesGpu[KeySize].create(runtime.context(), key)
    )

    @__parameter
    def bench[N: Int, suffix: StringLiteral]() raises:
        var data = Array[UInt8, N](fill=0)

        def do_encrypt() raises {mut data, mut runtime, cipher}:
            runtime.block_on(cipher.encrypt(runtime.context(), Span(data)))

        def do_decrypt() raises {mut data, mut runtime, cipher}:
            runtime.block_on(cipher.decrypt(runtime.context(), Span(data)))

        run(do_encrypt).print(prefix + "_encrypt_" + suffix)
        run(do_decrypt).print(prefix + "_decrypt_" + suffix)

    bench[BLOCKS_4K, "4kb"]()
    bench[BLOCKS_8K, "8kb"]()
    bench[BLOCKS_16K, "16kb"]()


def main() raises:
    print("Running AES GPU benchmarks")

    with DeviceContext() as ctx:
        var runtime = Runtime(ctx)
        bench_cipher[16, "aes128"](runtime)
        bench_cipher[24, "aes192"](runtime)
        bench_cipher[32, "aes256"](runtime)
