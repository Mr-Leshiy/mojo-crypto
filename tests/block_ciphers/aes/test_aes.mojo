from std.testing import assert_equal, TestSuite
from std.python import PythonObject
from std.reflection import reflect

from mojo_crypto.block_ciphers.aes import Aes, AesCpuBackend, BLOCK_SIZE
from mojo_crypto.block_ciphers.traits import BlockCipher
from mojo_crypto.block_ciphers.modes import CbcMode

from tests.block_ciphers.aes.utils import (
    AesTestVector,
    load_python_aes_vectors,
    load_aes_vectors,
)

comptime Backend[KeySize: Int] = AesCpuBackend[KeySize]


def check_aes_kat[
    C: BlockCipher & ImplicitlyDestructible,
    KeySize: Int,
    cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
](vectors: PythonObject) raises:
    for v in load_aes_vectors[KeySize](vectors):
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


# AES Known Answer Test (KAT) Vectors
# https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers#TDES
# https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/KAT_AES.zip
def test_aes_kat() raises:
    var vectors = load_python_aes_vectors(
        "tests/block_ciphers/aes/KAT_AES", "ECB"
    )

    @parameter
    def aes[
        KeySize: Int
    ](key: InlineArray[UInt8, KeySize]) raises -> Aes[
        KeySize, Backend[KeySize]
    ]:
        return Aes[KeySize](Backend[KeySize](key))

    check_aes_kat[Aes[16, Backend[16]], 16, aes[16]](vectors)
    check_aes_kat[Aes[24, Backend[24]], 24, aes[24]](vectors)
    check_aes_kat[Aes[32, Backend[32]], 32, aes[32]](vectors)


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

        var msg = "[{}], file_name={} count={}".format(
            reflect[C]().name(), v.file_name, v.count
        )
        assert_equal(block, expected, msg=msg)


# AES Monte Carlo Test (MCT) Sample Vectors
# https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers#TDES
# https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/aesmct.zip
def test_aes_mct() raises:
    var vectors = load_python_aes_vectors(
        "tests/block_ciphers/aes/aesmct", "ECB"
    )

    @parameter
    def aes[
        KeySize: Int
    ](key: InlineArray[UInt8, KeySize]) raises -> Aes[
        KeySize, Backend[KeySize]
    ]:
        return Aes[KeySize](Backend[KeySize](key))

    check_aes_mct[Aes[16, Backend[16]], 16, aes[16]](vectors)
    check_aes_mct[Aes[24, Backend[24]], 24, aes[24]](vectors)
    check_aes_mct[Aes[32, Backend[32]], 32, aes[32]](vectors)


def check_cbc_kat[
    C: BlockCipher & Movable & ImplicitlyDestructible,
    KeySize: Int,
    cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
](vectors: PythonObject) raises:
    for v in load_aes_vectors[KeySize](vectors):
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


# AES-CBC Known Answer Test (KAT) Vectors
# https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/KAT_AES.zip
def test_cbc_kat() raises:
    var vectors = load_python_aes_vectors(
        "tests/block_ciphers/aes/KAT_AES", "CBC"
    )

    @parameter
    def aes[
        KeySize: Int
    ](key: InlineArray[UInt8, KeySize]) raises -> Aes[
        KeySize, Backend[KeySize]
    ]:
        return Aes[KeySize](Backend[KeySize](key))

    check_cbc_kat[Aes[16, Backend[16]], 16, aes[16]](vectors)
    check_cbc_kat[Aes[24, Backend[24]], 24, aes[24]](vectors)
    check_cbc_kat[Aes[32, Backend[32]], 32, aes[32]](vectors)


def check_cbc_mct[
    C: BlockCipher & ImplicitlyDestructible,
    KeySize: Int,
    cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
](vectors: PythonObject) raises:
    # AESAVS CBC MCT inner loop (section 6.4.2).
    # Encrypt: XOR block with IB, AES-encrypt, then swap block↔IB.
    # Decrypt: AES-decrypt block, XOR with IB, then swap block↔IB.
    # After 1000 steps IB holds the expected CT (encrypt) or PT (decrypt).
    comptime MCT_INNER_ITERATIONS: Int = 1000

    for v in load_aes_vectors[KeySize](vectors):
        var cipher = cipher_init(v.key)
        var iv = v.iv.value()
        var msg = "[{}], file_name={} count={}".format(
            reflect[C]().name(), v.file_name, v.count
        )

        var ib = iv
        if v.is_encrypt:
            var block = v.pt
            for _ in range(MCT_INNER_ITERATIONS):
                for j in range(BLOCK_SIZE):
                    block[j] ^= ib[j]
                cipher.encrypt(block)
                var tmp = ib
                ib = block
                block = tmp
            assert_equal(ib, v.ct, msg=msg)
        else:
            var block = v.ct
            for _ in range(MCT_INNER_ITERATIONS):
                cipher.decrypt(block)
                for j in range(BLOCK_SIZE):
                    block[j] ^= ib[j]
                var tmp = ib
                ib = block
                block = tmp
            assert_equal(ib, v.pt, msg=msg)


# AES-CBC Monte Carlo Test (MCT) Sample Vectors
# https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/aesmct.zip
def test_cbc_mct() raises:
    var vectors = load_python_aes_vectors(
        "tests/block_ciphers/aes/aesmct", "CBC"
    )

    @parameter
    def aes[
        KeySize: Int
    ](key: InlineArray[UInt8, KeySize]) raises -> Aes[
        KeySize, Backend[KeySize]
    ]:
        return Aes[KeySize](Backend[KeySize](key))

    check_cbc_mct[Aes[16, Backend[16]], 16, aes[16]](vectors)
    check_cbc_mct[Aes[24, Backend[24]], 24, aes[24]](vectors)
    check_cbc_mct[Aes[32, Backend[32]], 32, aes[32]](vectors)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
