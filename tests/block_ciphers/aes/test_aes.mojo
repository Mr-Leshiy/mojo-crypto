from std.testing import assert_equal, TestSuite
from std.reflection import reflect
from std.sys import has_accelerator
from std.gpu.host import DeviceContext

from mojo_crypto.block_ciphers.aes import (
    Aes,
    AesCpuBackend,
    AesGpuBackend,
    BLOCK_SIZE,
)
from mojo_crypto.block_ciphers.traits import BlockCipher
from mojo_crypto.block_ciphers.modes import CbcMode

from tests.block_ciphers.aes.utils import (
    AesTestVector,
    load_python_acvp_vectors,
    parse_acvp_aes,
)

comptime Backend[KeySize: Int] = AesCpuBackend[KeySize]


def check_aes_kat[
    C: BlockCipher & Movable & ImplicitlyDestructible,
    KeySize: Int,
    cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
](dir: String) raises:
    for v in parse_acvp_aes[KeySize](load_python_acvp_vectors(dir, "AFT")):
        var cipher = cipher_init(v.key)
        var msg = "[{}], file_name={}, count={}".format(
            reflect[C]().name(), v.file_name, v.count
        )

        var pt = v.pt
        cipher.encrypt(pt)
        assert_equal(pt, v.ct, msg=msg)

        var ct = v.ct
        cipher.decrypt(ct)
        assert_equal(ct, v.pt, msg=msg)


def check_cbc_kat[
    C: BlockCipher & Movable & ImplicitlyDestructible,
    KeySize: Int,
    cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
](dir: String) raises:
    for v in parse_acvp_aes[KeySize, C.BLOCK_SIZE](
        load_python_acvp_vectors(dir, "AFT")
    ):
        var iv = v.iv.value()
        var msg = "[CbcMode[{}]], file_name={} count={}".format(
            reflect[C]().name(), v.file_name, v.count
        )

        var pt = v.pt
        var cbc_enc = CbcMode[C](cipher_init(v.key), iv)
        cbc_enc.encrypt(pt)
        assert_equal(pt, v.ct, msg=msg)

        var ct = v.ct
        var cbc_dec = CbcMode[C](cipher_init(v.key), iv)
        cbc_dec.decrypt(ct)
        assert_equal(ct, v.pt, msg=msg)


def check_aes_mct[
    C: BlockCipher & Movable & ImplicitlyDestructible,
    KeySize: Int,
    cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
](dir: String) raises:
    # Number of inner iterations per MCT outer loop, as specified in AESAVS section 6.4.1:
    # https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf
    comptime MCT_INNER_ITERATIONS: Int = 1000

    for v in parse_acvp_aes[KeySize](load_python_acvp_vectors(dir, "MCT")):
        var initial = v.pt if v.is_encrypt else v.ct
        var expected = v.ct if v.is_encrypt else v.pt
        var cipher = cipher_init(v.key)
        var block = initial
        for _ in range(MCT_INNER_ITERATIONS):
            if v.is_encrypt:
                cipher.encrypt(block)
            else:
                cipher.decrypt(block)

        var msg = "[{}], file_name={} count={}".format(
            reflect[C]().name(), v.file_name, v.count
        )
        assert_equal(block, expected, msg=msg)


def check_cbc_mct[
    C: BlockCipher & Movable & ImplicitlyDestructible,
    KeySize: Int,
    cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
](dir: String) raises:
    comptime MCT_INNER_ITERATIONS: Int = 1000

    for v in parse_acvp_aes[KeySize, C.BLOCK_SIZE](
        load_python_acvp_vectors(dir, "MCT")
    ):
        var msg = "[CbcMode[{}]], file_name={} count={}".format(
            reflect[C]().name(), v.file_name, v.count
        )

        if v.is_encrypt:
            var block = v.pt
            var next_block = v.iv.value()
            var cbc = CbcMode[C](cipher_init(v.key), v.iv.value())
            for _ in range(MCT_INNER_ITERATIONS):
                cbc.encrypt(block)
                var tmp = block
                block = next_block
                next_block = tmp
            assert_equal(next_block, v.ct, msg=msg)
        else:
            var block = v.ct
            var next_block = v.iv.value()
            var cbc = CbcMode[C](cipher_init(v.key), v.iv.value())
            for _ in range(MCT_INNER_ITERATIONS):
                cbc.decrypt(block)
                var tmp = block
                block = next_block
                next_block = tmp
            assert_equal(next_block, v.pt, msg=msg)


def run_checks[
    check: def[
        C: BlockCipher & Movable & ImplicitlyDestructible,
        KeySize: Int,
        cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
    ](String) raises capturing[_]
](dir: String) raises:
    comptime if has_accelerator():
        with DeviceContext() as ctx:

            @parameter
            def aes_gpu[
                KeySize: Int
            ](key: InlineArray[UInt8, KeySize]) raises -> Aes[
                KeySize, AesGpuBackend[KeySize]
            ]:
                return Aes[KeySize](AesGpuBackend[KeySize](ctx, key))

            check[Aes[16, AesGpuBackend[16]], 16, aes_gpu[16]](dir)
            check[Aes[24, AesGpuBackend[24]], 24, aes_gpu[24]](dir)
            check[Aes[32, AesGpuBackend[32]], 32, aes_gpu[32]](dir)

    @parameter
    def aes_cpu[
        KeySize: Int
    ](key: InlineArray[UInt8, KeySize]) raises -> Aes[
        KeySize, AesCpuBackend[KeySize]
    ]:
        return Aes[KeySize](AesCpuBackend[KeySize](key))

    check[Aes[16, AesCpuBackend[16]], 16, aes_cpu[16]](dir)
    check[Aes[24, AesCpuBackend[24]], 24, aes_cpu[24]](dir)
    check[Aes[32, AesCpuBackend[32]], 32, aes_cpu[32]](dir)


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ACVP-AES-ECB-1.0
def test_aes_kat() raises:
    run_checks[check_aes_kat]("tests/block_ciphers/aes/acvp/ACVP-AES-ECB-1.0")


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ACVP-AES-CBC-1.0
def test_cbc_kat() raises:
    run_checks[check_cbc_kat]("tests/block_ciphers/aes/acvp/ACVP-AES-CBC-1.0")


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ACVP-AES-ECB-1.0
def test_aes_mct() raises:
    run_checks[check_aes_mct]("tests/block_ciphers/aes/acvp/ACVP-AES-ECB-1.0")


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ACVP-AES-CBC-1.0
def test_cbc_mct() raises:
    run_checks[check_cbc_mct]("tests/block_ciphers/aes/acvp/ACVP-AES-CBC-1.0")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
