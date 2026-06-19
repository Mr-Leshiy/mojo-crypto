from std.testing import assert_equal, TestSuite
from std.python import PythonObject
from std.reflection import reflect
from std.sys import has_accelerator
from std.gpu.host import DeviceContext

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
from mojo_crypto.block_ciphers.modes import CbcMode, CtrMode

from tests.block_ciphers.aes.utils import (
    AesTestVector,
    load_python_acvp_vectors,
    parse_acvp_aes,
)


def check_aes_eft[
    C: BlockCipherEncryptable
    & BlockCipherDecryptable
    & Movable
    & ImplicitlyDestructible,
    KeySize: Int,
    cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
](vectors: PythonObject) raises:
    checked_at_least_once = False
    for v in parse_acvp_aes(vectors):
        if len(v.key) != KeySize:
            continue

        checked_at_least_once = True

        var msg = "[{}], file_name={}, count={}".format(
            reflect[C]().name(), v.file_name, v.count
        )

        var cipher = cipher_init(to_inline_array[KeySize](v.key))

        var pt = v.pt.copy()
        cipher.encrypt(pt[:])
        assert_equal(pt, v.ct, msg=msg)

        var ct = v.ct.copy()
        cipher.decrypt(ct[:])
        assert_equal(ct, v.pt, msg=msg)

    assert_equal(checked_at_least_once, True)


def check_aes_cbc_eft[
    C: BlockCipherEncryptable
    & BlockCipherDecryptable
    & Movable
    & ImplicitlyDestructible,
    KeySize: Int,
    cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
](vectors: PythonObject) raises:
    checked_at_least_once = False
    for v in parse_acvp_aes(vectors):
        if len(v.key) != KeySize:
            continue
        
        checked_at_least_once = True

        var msg = "[CbcMode[{}]], file_name={} count={}".format(
            reflect[C]().name(), v.file_name, v.count
        )

        var key = to_inline_array[KeySize](v.key)
        var iv = to_inline_array[C.BLOCK_SIZE](v.iv)
        var pt = v.pt.copy()

        var cbc_enc = CbcMode[C](cipher_init(key), iv)
        cbc_enc.encrypt(pt[:])
        assert_equal(pt, v.ct, msg=msg)

        var ct = v.ct.copy()
        var cbc_dec = CbcMode[C](cipher_init(key), iv)
        cbc_dec.decrypt(ct[:])
        assert_equal(ct, v.pt, msg=msg)

    assert_equal(checked_at_least_once, True)


def check_aes_mct[
    C: BlockCipherEncryptable
    & BlockCipherDecryptable
    & Movable
    & ImplicitlyDestructible,
    KeySize: Int,
    cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
](vectors: PythonObject) raises:
    # Number of inner iterations per MCT outer loop, as specified in AESAVS section 6.4.1:
    # https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf
    comptime MCT_INNER_ITERATIONS: Int = 1000

    checked_at_least_once = False
    for v in parse_acvp_aes(vectors):
        if len(v.key) != KeySize:
            continue
        
        checked_at_least_once = True

        var block = v.pt.copy() if v.is_encrypt else v.ct.copy()
        var expected = v.ct.copy() if v.is_encrypt else v.pt.copy()
        var key = to_inline_array[KeySize](v.key)

        var cipher = cipher_init(key)
        for _ in range(MCT_INNER_ITERATIONS):
            if v.is_encrypt:
                cipher.encrypt(block[:])
            else:
                cipher.decrypt(block[:])

        var msg = "[{}], file_name={} count={}".format(
            reflect[C]().name(), v.file_name, v.count
        )
        assert_equal(block, expected, msg=msg)

    assert_equal(checked_at_least_once, True)


def check_aes_cbc_mct[
    C: BlockCipherEncryptable
    & BlockCipherDecryptable
    & Movable
    & ImplicitlyDestructible,
    KeySize: Int,
    cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
](vectors: PythonObject) raises:
    comptime MCT_INNER_ITERATIONS: Int = 1000

    checked_at_least_once = False
    for v in parse_acvp_aes(vectors):
        if len(v.key) != KeySize:
            continue

        checked_at_least_once = True
        
        var msg = "[CbcMode[{}]], file_name={} count={}".format(
            reflect[C]().name(), v.file_name, v.count
        )

        var key = to_inline_array[KeySize](v.key)
        var iv = to_inline_array[C.BLOCK_SIZE](v.iv)

        if v.is_encrypt:
            var block = v.pt.copy()
            var next_block = v.iv.copy()
            var cbc = CbcMode[C](cipher_init(key), iv)
            for _ in range(MCT_INNER_ITERATIONS):
                cbc.encrypt(block[:])
                var tmp = block^
                block = next_block^
                next_block = tmp^
            assert_equal(next_block, v.ct, msg=msg)
        else:
            var block = v.ct.copy()
            var next_block = v.iv.copy()
            var cbc = CbcMode[C](cipher_init(key), iv)
            for _ in range(MCT_INNER_ITERATIONS):
                cbc.decrypt(block[:])
                var tmp = block^
                block = next_block^
                next_block = tmp^
            assert_equal(next_block, v.pt, msg=msg)

    assert_equal(checked_at_least_once, True)


def check_aes_ctr_mct[
    C: BlockCipherEncryptable
    & BlockCipherDecryptable
    & Movable
    & ImplicitlyDestructible,
    KeySize: Int,
    cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
](vectors: PythonObject) raises:
    # AESAVS CTR MCT: 1000 inner iterations, chaining CT → PT each step.
    # CtrMode maintains counter state across calls, so one instance covers all
    # 1000 blocks (counter increments by 1 per block, matching ICB_j = ICB_0+j).
    comptime MCT_INNER_ITERATIONS: Int = 1000

    checked_at_least_once = False
    for v in parse_acvp_aes(vectors):
        if len(v.key) != KeySize:
            continue

        checked_at_least_once = True

        var msg = "[CtrMode[{}]], file_name={} count={}".format(
            reflect[C]().name(), v.file_name, v.count
        )

        var key = to_inline_array[KeySize](v.key)
        var iv = to_inline_array[C.BLOCK_SIZE](v.iv)
        var block = v.pt.copy() if v.is_encrypt else v.ct.copy()
        var expected = v.ct.copy() if v.is_encrypt else v.pt.copy()

        var ctr = CtrMode[C](cipher_init(key), iv)
        for _ in range(MCT_INNER_ITERATIONS):
            if v.is_encrypt:
                ctr.encrypt(block[:])
            else:
                ctr.decrypt(block[:])
        assert_equal(block, expected, msg=msg)

    assert_equal(checked_at_least_once, True)


def check_aes_ctr_aft[
    C: BlockCipherEncryptable
    & BlockCipherDecryptable
    & Movable
    & ImplicitlyDestructible,
    KeySize: Int,
    cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
](vectors: PythonObject) raises:
    checked_at_least_once = False
    for v in parse_acvp_aes(vectors):
        if len(v.key) != KeySize:
            continue

        checked_at_least_once = True

        var msg = "[CtrMode[{}]], file_name={} count={}".format(
            reflect[C]().name(), v.file_name, v.count
        )

        var key = to_inline_array[KeySize](v.key)
        var iv = to_inline_array[C.BLOCK_SIZE](v.iv)

        if v.is_encrypt:
            var pt = v.pt.copy()
            var ctr = CtrMode[C](cipher_init(key), iv)
            ctr.encrypt(pt[:])
            assert_equal(pt, v.ct, msg=msg)
        else:
            var ct = v.ct.copy()
            var ctr = CtrMode[C](cipher_init(key), iv)
            ctr.decrypt(ct[:])
            assert_equal(ct, v.pt, msg=msg)

    assert_equal(checked_at_least_once, True)


def run_checks[
    check: def[
        C: BlockCipherEncryptable
        & BlockCipherDecryptable
        & Movable
        & ImplicitlyDestructible,
        KeySize: Int,
        cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
    ](PythonObject) raises capturing[_]
](vectors: PythonObject) raises:
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

    @parameter
    def aes_cpu[
        KeySize: Int
    ](key: InlineArray[UInt8, KeySize]) raises -> AesCpu[KeySize]:
        return AesCpu[KeySize](key)

    check[AesCpu[16], 16, aes_cpu[16]](vectors)
    check[AesCpu[24], 24, aes_cpu[24]](vectors)
    check[AesCpu[32], 32, aes_cpu[32]](vectors)

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


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ACVP-AES-ECB-1.0
def test_aes_aft() raises:
    var vectors = load_python_acvp_vectors(
        "tests/block_ciphers/aes/acvp/ACVP-AES-ECB-1.0", "AFT"
    )
    run_checks[check_aes_eft](vectors)


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ACVP-AES-CBC-1.0
def test_aes_cbc_aft() raises:
    var vectors = load_python_acvp_vectors(
        "tests/block_ciphers/aes/acvp/ACVP-AES-CBC-1.0", "AFT"
    )
    run_checks[check_aes_cbc_eft](vectors)


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ACVP-AES-ECB-1.0
def test_aes_mct() raises:
    var vectors = load_python_acvp_vectors(
        "tests/block_ciphers/aes/acvp/ACVP-AES-ECB-1.0", "MCT"
    )
    run_checks[check_aes_mct](vectors)


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ACVP-AES-CBC-1.0
def test_aes_cbc_mct() raises:
    var vectors = load_python_acvp_vectors(
        "tests/block_ciphers/aes/acvp/ACVP-AES-CBC-1.0", "MCT"
    )
    run_checks[check_aes_cbc_mct](vectors)


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ACVP-AES-CTR-1.0
def test_aes_ctr_aft() raises:
    var vectors = load_python_acvp_vectors(
        "tests/block_ciphers/aes/acvp/ACVP-AES-CTR-1.0", "AFT"
    )
    run_checks[check_aes_ctr_aft](vectors)


def test_aes_ctr_mct() raises:
    var vectors = load_python_acvp_vectors(
        "tests/block_ciphers/aes/acvp/ACVP-AES-CTR-1.0", "MCT"
    )
    run_checks[check_aes_ctr_mct](vectors)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
