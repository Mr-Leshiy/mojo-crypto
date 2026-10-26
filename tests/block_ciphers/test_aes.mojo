from std.testing import assert_equal, TestSuite
from std.reflection import reflect
from max.gpu.host import DeviceContext

from mojo_crypto.utils import to_array
from mojo_crypto.utils.hex import hex_decode

from tests.block_ciphers.utils import (
    AesFactory,
    AesAarch64Factory,
    AesGpuFactory,
    AesNaiveFactory,
    AesX86Factory,
)
from tests.platform import HAS_AES_AARCH64, HAS_AES_X86, HAS_GPU


@fieldwise_init
struct AesTestVector(Copyable, Movable):
    var key: List[UInt8]
    var pt: List[UInt8]
    var ct: List[UInt8]


def check_aes[F: AesFactory](factory: F, vectors: List[AesTestVector]) raises:
    var msg = "[{}], key_size={}".format(reflect[F.Cipher].name(), F.KEY_SIZE)
    for v in vectors:
        var cipher = factory.create(to_array[F.KEY_SIZE](v.key))

        var pt = v.pt.copy()
        cipher.encrypt(pt[:])
        assert_equal(pt, v.ct, msg=msg)

        var ct = v.ct.copy()
        cipher.decrypt(ct[:])
        assert_equal(ct, v.pt, msg=msg)


# Single-block known-answer vectors for AES-128/192/256
# from FIPS 197 Appendix C
# https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
def fips197_aes128_vectors() raises -> List[AesTestVector]:
    return [
        AesTestVector(
            key=hex_decode("000102030405060708090a0b0c0d0e0f"),
            pt=hex_decode("00112233445566778899aabbccddeeff"),
            ct=hex_decode("69c4e0d86a7b0430d8cdb78070b4c55a"),
        ),
    ]


def fips197_aes192_vectors() raises -> List[AesTestVector]:
    return [
        AesTestVector(
            key=hex_decode("000102030405060708090a0b0c0d0e0f1011121314151617"),
            pt=hex_decode("00112233445566778899aabbccddeeff"),
            ct=hex_decode("dda97ca4864cdfe06eaf70a0ec0d7191"),
        ),
    ]


def fips197_aes256_vectors() raises -> List[AesTestVector]:
    return [
        AesTestVector(
            key=hex_decode(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            ),
            pt=hex_decode("00112233445566778899aabbccddeeff"),
            ct=hex_decode("8ea2b7ca516745bfeafc49904b496089"),
        ),
    ]


def test_aes128_fips197_naive() raises:
    check_aes(AesNaiveFactory[16](), fips197_aes128_vectors())


def test_aes192_fips197_naive() raises:
    check_aes(AesNaiveFactory[24](), fips197_aes192_vectors())


def test_aes256_fips197_naive() raises:
    check_aes(AesNaiveFactory[32](), fips197_aes256_vectors())


def test_aes128_fips197_aarch64() raises:
    check_aes(AesAarch64Factory[16](), fips197_aes128_vectors())


def test_aes192_fips197_aarch64() raises:
    check_aes(AesAarch64Factory[24](), fips197_aes192_vectors())


def test_aes256_fips197_aarch64() raises:
    check_aes(AesAarch64Factory[32](), fips197_aes256_vectors())


def test_aes128_fips197_x86() raises:
    check_aes(AesX86Factory[16](), fips197_aes128_vectors())


def test_aes192_fips197_x86() raises:
    check_aes(AesX86Factory[24](), fips197_aes192_vectors())


def test_aes256_fips197_x86() raises:
    check_aes(AesX86Factory[32](), fips197_aes256_vectors())


def test_aes128_fips197_gpu() raises:
    with DeviceContext() as ctx:
        check_aes(AesGpuFactory[16](ctx), fips197_aes128_vectors())


def test_aes192_fips197_gpu() raises:
    with DeviceContext() as ctx:
        check_aes(AesGpuFactory[24](ctx), fips197_aes192_vectors())


def test_aes256_fips197_gpu() raises:
    with DeviceContext() as ctx:
        check_aes(AesGpuFactory[32](ctx), fips197_aes256_vectors())


def main() raises:
    var suite = TestSuite()

    suite.test[test_aes128_fips197_naive]()
    suite.test[test_aes192_fips197_naive]()
    suite.test[test_aes256_fips197_naive]()

    comptime if HAS_AES_AARCH64:
        suite.test[test_aes128_fips197_aarch64]()
        suite.test[test_aes192_fips197_aarch64]()
        suite.test[test_aes256_fips197_aarch64]()

    comptime if HAS_AES_X86:
        suite.test[test_aes128_fips197_x86]()
        suite.test[test_aes192_fips197_x86]()
        suite.test[test_aes256_fips197_x86]()

    comptime if HAS_GPU:
        suite.test[test_aes128_fips197_gpu]()
        suite.test[test_aes192_fips197_gpu]()
        suite.test[test_aes256_fips197_gpu]()

    suite^.run()
