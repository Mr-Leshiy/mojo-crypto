from std.python import Python, PythonObject
from std.sys import has_accelerator
from std.gpu.host import DeviceContext

from mojo_crypto.containers.encoding import Hex
from mojo_crypto.utils import target_triple_contains_any, to_inline_array
from mojo_crypto.block_ciphers.aes import (
    AesCpu,
    AesAarch64,
    AesX86,
    AesGpu,
)
from mojo_crypto.block_ciphers.traits import (
    BlockCipherDecryptable,
    BlockCipherEncryptable,
)


@fieldwise_init
struct AesTestVector(Copyable, Movable):
    var is_encrypt: Bool
    var count: Int
    var key: List[UInt8]
    # Fixed 16-byte IV for the block-cipher modes (CBC/CTR); None otherwise.
    var iv: List[UInt8]
    var pt: List[UInt8]
    var ct: List[UInt8]
    var file_name: String
    # AEAD (GCM) fields; empty / default for the block-cipher modes.
    # GCM nonce is variable length (commonly 12 bytes), so not a fixed array.
    var aad: List[UInt8]
    # Authentication tag, possibly truncated (tagLen varies per group).
    var tag: List[UInt8]
    # For decrypt vectors: whether authentication is expected to succeed.
    var test_passed: Bool


def load_python_acvp_vectors(
    dir: String, test_type: String
) raises -> PythonObject:
    var sys = Python.import_module("sys")
    sys.path.insert(0, PythonObject("tests/block_ciphers/aes"))
    var read_acvp_vectors = Python.import_module("read_acvp_vectors")
    return read_acvp_vectors.load(dir, read_acvp_vectors.TestType(test_type))


def load_python_acvp_vectors_2(
    dir: String, test_type: String
) raises -> PythonObject:
    var sys = Python.import_module("sys")
    sys.path.insert(0, PythonObject("tests/block_ciphers/aes"))
    var read_acvp_vectors = Python.import_module("read_acvp_vectors")
    return read_acvp_vectors.load_2(dir, read_acvp_vectors.TestType(test_type))


def parse_acvp_aes(
    python_vectors: PythonObject,
) raises -> List[AesTestVector]:
    var vectors = List[AesTestVector]()
    hex = Hex()
    for v in python_vectors:
        var iv = List[UInt8]()
        if v.iv_hex is not Python.none():
            iv = hex.decode(String(v.iv_hex))
        var aad = List[UInt8]()
        if v.aad_hex is not Python.none():
            aad = hex.decode(String(v.aad_hex))
        var tag = List[UInt8]()
        if v.tag_hex is not Python.none():
            tag = hex.decode(String(v.tag_hex))
        vectors.append(
            AesTestVector(
                is_encrypt=v.is_encrypt.__bool__(),
                count=atol(String(v.count)),
                key=hex.decode(String(v.key_hex)),
                iv=iv^,
                pt=hex.decode(String(v.pt_hex)),
                ct=hex.decode(String(v.ct_hex)),
                file_name=String(""),
                aad=aad^,
                tag=tag^,
                test_passed=v.test_passed.__bool__(),
            )
        )
    return vectors^


def run_checks[
    Vectors: AnyType,
    //,
    check: def[
        C: BlockCipherEncryptable
        & BlockCipherDecryptable
        & Copyable
        & Movable
        & ImplicitlyDestructible,
        KeySize: Int,
        cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
    ](Vectors) raises capturing[_]
](vectors: Vectors) raises:
    comptime if has_accelerator():
        with DeviceContext() as ctx:

            @parameter
            def aes_gpu[
                KeySize: Int
            ](key: InlineArray[UInt8, KeySize]) raises -> AesGpu[KeySize]:
                return AesGpu[KeySize](ctx, key)

            check[AesGpu[16], 16, aes_gpu[16]](vectors)
            check[AesGpu[24], 24, aes_gpu[24]](vectors)
            check[AesGpu[32], 32, aes_gpu[32]](vectors)

    comptime if target_triple_contains_any(["aarch64", "arm64"]):

        @parameter
        def aes_aarch64[
            KeySize: Int
        ](key: InlineArray[UInt8, KeySize]) raises -> AesAarch64[KeySize]:
            return AesAarch64[KeySize](key)

        check[AesAarch64[16], 16, aes_aarch64[16]](vectors)
        check[AesAarch64[24], 24, aes_aarch64[24]](vectors)
        check[AesAarch64[32], 32, aes_aarch64[32]](vectors)

    comptime if target_triple_contains_any(["x86_64"]):

        @parameter
        def aes_x86[
            KeySize: Int
        ](key: InlineArray[UInt8, KeySize]) raises -> AesX86[KeySize]:
            return AesX86[KeySize](key)

        check[AesX86[16], 16, aes_x86[16]](vectors)
        check[AesX86[24], 24, aes_x86[24]](vectors)
        check[AesX86[32], 32, aes_x86[32]](vectors)

    @parameter
    def aes_cpu[
        KeySize: Int
    ](key: InlineArray[UInt8, KeySize]) raises -> AesCpu[KeySize]:
        return AesCpu[KeySize](key)

    check[AesCpu[16], 16, aes_cpu[16]](vectors)
    check[AesCpu[24], 24, aes_cpu[24]](vectors)
    check[AesCpu[32], 32, aes_cpu[32]](vectors)
