from std.gpu.host import DeviceContext
from std.testing import assert_equal, TestSuite
from std.python import PythonObject
from std.reflection import reflect

from mojo_crypto.aes import Aes, BLOCK_SIZE
from mojo_crypto.block_cipher import BlockCipher

from tests.aes.utils import (
    AesTestVector,
    load_python_aes_vectors,
    load_aes_vectors,
)


def test_aes_128() raises:
    def check_aes(
        plaintext: InlineArray[UInt8, 16],
        key: InlineArray[UInt8, 16],
        expected: InlineArray[UInt8, 16],
    ) raises:
        var aes = Aes[16](key)
        var block = plaintext
        aes.encrypt(block)
        assert_equal(block, expected)
        aes.decrypt(block)
        assert_equal(block, plaintext)

    # FIPS 197 Appendix B
    check_aes(
        [
            # fmt: off
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
            # fmt: on
        ],
        [
            # fmt: off
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
            # fmt: on
        ],
        [
            # fmt: off
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
            0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32,
            # fmt: on
        ],
    )

    # FIPS 197 Appendix C.1
    check_aes(
        [
            # fmt: off
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            # fmt: on
        ],
        [
            # fmt: off
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            # fmt: on
        ],
        [
            # fmt: off
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
            0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
            # fmt: on
        ],
    )


def check_aes_kat[
    C: BlockCipher & ImplicitlyDestructible,
    KeySize: Int,
    cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
](vectors: PythonObject) raises:
    for v in load_aes_vectors[KeySize](vectors):
        var cipher = cipher_init(v.key)
        var msg = "[{}], file_name={}".format(reflect[C]().name(), v.file_name)

        var pt = v.pt
        cipher.encrypt(pt)
        assert_equal(pt, v.ct, msg=msg)

        var ct = v.ct
        cipher.decrypt(ct)
        assert_equal(ct, v.pt, msg=msg)


# AES Known Answer Test (KAT) Vectors
# https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers#TDES
# https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/KAT_AES.zip
def test_aes_kat() raises:
    var vectors = load_python_aes_vectors("tests/aes/KAT_AES", "ECB")

    with DeviceContext() as ctx:

        @parameter
        def aes[
            KeySize: Int
        ](key: InlineArray[UInt8, KeySize]) raises -> Aes[KeySize]:
            return Aes[KeySize](key)

        @parameter
        def aes_gpu[
            KeySize: Int
        ](key: InlineArray[UInt8, KeySize]) raises -> Aes[KeySize]:
            return Aes[KeySize](key, ctx)
        
        check_aes_kat[Aes[16], 16, aes[16]](vectors)
        check_aes_kat[Aes[24], 24, aes[24]](vectors)
        check_aes_kat[Aes[32], 32, aes[32]](vectors)

        check_aes_kat[Aes[16], 16, aes_gpu[16]](vectors)
        check_aes_kat[Aes[24], 24, aes_gpu[24]](vectors)
        check_aes_kat[Aes[32], 32, aes_gpu[32]](vectors)


def check_aes_mct[
    C: BlockCipher & ImplicitlyDestructible,
    KeySize: Int,
    cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
](vectors: PythonObject) raises:
    # Number of inner iterations per MCT outer loop, as specified in AESAVS section 6.4.1:
    # https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf
    comptime MCT_INNER_ITERATIONS: Int = 1000

    for v in load_aes_vectors[KeySize](vectors):
        var initial = v.pt if v.is_encrypt else v.ct
        var expected = v.ct if v.is_encrypt else v.pt
        var cipher = cipher_init(v.key)
        var block = initial
        for _ in range(MCT_INNER_ITERATIONS):
            if v.is_encrypt:
                cipher.encrypt(block)
            else:
                cipher.decrypt(block)

        var msg = "[{}], file_name={}".format(reflect[C]().name(), v.file_name)
        assert_equal(block, expected, msg=msg)


# AES Monte Carlo Test (MCT) Sample Vectors
# https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers#TDES
# https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/aesmct.zip
def aes_mct() raises:
    var vectors = load_python_aes_vectors("tests/aes/aesmct", "ECB")

    with DeviceContext() as ctx:

        @parameter
        def aes[
            KeySize: Int
        ](key: InlineArray[UInt8, KeySize]) raises -> Aes[KeySize]:
            return Aes[KeySize](key)

        @parameter
        def aes_gpu[
            KeySize: Int
        ](key: InlineArray[UInt8, KeySize]) raises -> Aes[KeySize]:
            return Aes[KeySize](key, ctx)

        check_aes_mct[Aes[16], 16, aes[16]](vectors)
        check_aes_mct[Aes[24], 24, aes[24]](vectors)
        check_aes_mct[Aes[32], 32, aes[32]](vectors)

        check_aes_mct[Aes[16], 16, aes_gpu[16]](vectors)
        check_aes_mct[Aes[24], 24, aes_gpu[24]](vectors)
        check_aes_mct[Aes[32], 32, aes_gpu[32]](vectors)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
