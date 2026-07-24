from std.testing import assert_equal, TestSuite
from std.math import min

from mojo_crypto.block_ciphers.aes import AesNaive
from mojo_crypto.containers.encoding import Hex
from mojo_crypto.macs import Cmac


def check_cmac_test_vector[
    KEY_SIZE: Int
](key_hex: String, msg_hex: String, expected_hex: String) raises:
    var hex = Hex()
    var key = hex.decode[KEY_SIZE](key_hex)
    var msg = hex.decode(msg_hex)
    var expected = hex.decode[16](expected_hex)

    var cmac = Cmac[AesNaive[KEY_SIZE]](AesNaive[KEY_SIZE](key))
    cmac.update(msg)
    assert_equal(cmac^.finalize(), expected)


# Test vectors from RFC 4493 Section 4 (also in NIST SP 800-38B Appendix D.2):
# https://www.rfc-editor.org/rfc/rfc4493
def test_aes128_cmac() raises:
    comptime KEY = "2b7e151628aed2a6abf7158809cf4f3c"

    check_cmac_test_vector[16](KEY, "", "bb1d6929e95937287fa37d129b756746")
    check_cmac_test_vector[16](
        KEY,
        "6bc1bee22e409f96e93d7e117393172a",
        "070a16b46b4d4144f79bdd9dd04a287c",
    )
    check_cmac_test_vector[16](
        KEY,
        "6bc1bee22e409f96e93d7e117393172a"
        + "ae2d8a571e03ac9c9eb76fac45af8e51"
        + "30c81c46a35ce411",
        "dfa66747de9ae63030ca32611497c827",
    )
    check_cmac_test_vector[16](
        KEY,
        "6bc1bee22e409f96e93d7e117393172a"
        + "ae2d8a571e03ac9c9eb76fac45af8e51"
        + "30c81c46a35ce411e5fbc1191a0a52ef"
        + "f69f2445df4f9b17ad2b417be66c3710",
        "51f0bebf7e3b9d92fc49741779363cfe",
    )


# Test vectors from NIST SP 800-38B Appendix D.2 (updated values):
# https://csrc.nist.gov/publications/nistpubs/800-38B/Updated_CMAC_Examples.pdf
def test_aes192_cmac() raises:
    comptime KEY = "8e73b0f7da0e6452c810f32b809079e5" + "62f8ead2522c6b7b"

    check_cmac_test_vector[24](KEY, "", "d17ddf46adaacde531cac483de7a9367")
    check_cmac_test_vector[24](
        KEY,
        "6bc1bee22e409f96e93d7e117393172a",
        "9e99a7bf31e710900662f65e617c5184",
    )
    check_cmac_test_vector[24](
        KEY,
        "6bc1bee22e409f96e93d7e117393172a"
        + "ae2d8a571e03ac9c9eb76fac45af8e51"
        + "30c81c46a35ce411",
        "8a1de5be2eb31aad089a82e6ee908b0e",
    )
    check_cmac_test_vector[24](
        KEY,
        "6bc1bee22e409f96e93d7e117393172a"
        + "ae2d8a571e03ac9c9eb76fac45af8e51"
        + "30c81c46a35ce411e5fbc1191a0a52ef"
        + "f69f2445df4f9b17ad2b417be66c3710",
        "a1d5df0eed790f794d77589659f39a11",
    )


# Test vectors from NIST SP 800-38B Appendix D.3:
# https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38b.pdf
def test_aes256_cmac() raises:
    comptime KEY = "603deb1015ca71be2b73aef0857d7781" + "1f352c073b6108d72d9810a30914dff4"

    check_cmac_test_vector[32](KEY, "", "028962f61b7bf89efc6b551f4667d983")
    check_cmac_test_vector[32](
        KEY,
        "6bc1bee22e409f96e93d7e117393172a",
        "28a7023f452e8f82bd4bf28d8c37c35c",
    )
    check_cmac_test_vector[32](
        KEY,
        "6bc1bee22e409f96e93d7e117393172a"
        + "ae2d8a571e03ac9c9eb76fac45af8e51"
        + "30c81c46a35ce411",
        "aaf3d8f1de5640c232f5b169b9c911e6",
    )
    check_cmac_test_vector[32](
        KEY,
        "6bc1bee22e409f96e93d7e117393172a"
        + "ae2d8a571e03ac9c9eb76fac45af8e51"
        + "30c81c46a35ce411e5fbc1191a0a52ef"
        + "f69f2445df4f9b17ad2b417be66c3710",
        "e1992190549f6ed5696a2c056c315410",
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
