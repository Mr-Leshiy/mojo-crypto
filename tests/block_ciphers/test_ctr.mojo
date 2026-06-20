from std.testing import assert_equal, TestSuite

from mojo_crypto.block_ciphers.aes import AesCpu
from mojo_crypto.block_ciphers.modes import CtrMode
from mojo_crypto.containers.encoding import Hex


# Reference vectors from RustCrypto `block-modes`:
# https://github.com/RustCrypto/block-modes/blob/master/ctr/tests/ctr32/le.rs
def test_ctr_32_le_aes() raises:
    var hex = Hex()
    var key = hex.decode[16]("000102030405060708090A0B0C0D0E0F")
    var iv = hex.decode[16]("11111111111111111111111111111191")

    comptime CTR = CtrMode[AesCpu[16], 4, BIG_ENDIAN=False]

    # `counter_incr`: encrypting 64 zero bytes yields the raw keystream.
    var ks_expected = hex.decode[64](
        "2A0680B210CAD45E886D7EF6DAB357C9"
        + "F18B39AFF6930FDB2D9FCE34261FF699"
        + "EB96774669D24B560C9AD028C5C39C45"
        + "80775A82065256B4787DC91C6942B700"
    )
    
    var zeros = InlineArray[UInt8, 64](fill=0)
    var ctr = CTR(AesCpu[16](key), iv)
    ctr.encrypt(zeros)
    assert_equal(zeros, ks_expected, msg="counter_incr")

    # `keystream_xor`: encrypting 64 bytes of 0x01 yields keystream XOR 0x01.
    var xor_expected = hex.decode[64](
        "2B0781B311CBD55F896C7FF7DBB256C8"
        + "F08A38AEF7920EDA2C9ECF35271EF798"
        + "EA97764768D34A570D9BD129C4C29D44"
        + "81765B83075357B5797CC81D6843B601"
    )
    var ones = InlineArray[UInt8, 64](fill=1)
    var ctr2 = CTR(AesCpu[16](key), iv)
    ctr2.encrypt(ones)
    assert_equal(ones, xor_expected, msg="keystream_xor")

    # `counter_wrap`: NONCE2 starts the LE counter at 0xFFFFFFFE, so the 4-block
    # (64-byte) keystream crosses the 32-bit wrap (..FE, ..FF, 0, 1) without the
    # carry escaping into the nonce.
    var iv2 = hex.decode[16]("FEFFFFFF2222222222222222222222A2")
    var wrap_expected = hex.decode[64](
        "A1E649D8B382293DC28375C42443BB6A"
        + "226BAADC9E9CCA8214F56E07A4024E06"
        + "6355A0DA2E08FB00112FFA38C26189EE"
        + "55DD5B0B130ED87096FE01B59A665A60"
    )
    var wrap = InlineArray[UInt8, 64](fill=0)
    var ctr3 = CTR(AesCpu[16](key), iv2)
    ctr3.encrypt(wrap)
    assert_equal(wrap, wrap_expected, msg="counter_wrap")


# Reference vectors from RustCrypto `block-modes`:
# https://github.com/RustCrypto/block-modes/blob/master/ctr/tests/ctr32/be.rs
def test_ctr_32_be_aes() raises:
    var hex = Hex()
    var key = hex.decode[16]("000102030405060708090A0B0C0D0E0F")
    var iv = hex.decode[16]("11111111111111111111111111111111")

    comptime CTR = CtrMode[AesCpu[16], 4, BIG_ENDIAN=True]

    # `counter_incr`: encrypting 64 zero bytes yields the raw keystream.
    var ks_expected = hex.decode[64](
        "35D14E6D3E3A279CF01E343E34E7DED3"
        + "6EEADB04F42E2251AB4377F257856DBA"
        + "0AB37657B9C2AA09762E518FC9395D53"
        + "04E96C34CCD2F0A95CDE7321852D90C0"
    )
    var zeros = InlineArray[UInt8, 64](fill=0)
    var ctr = CTR(AesCpu[16](key), iv)
    ctr.encrypt(zeros)
    assert_equal(zeros, ks_expected, msg="counter_incr")

    # `keystream_xor`: encrypting 64 bytes of 0x01 yields keystream XOR 0x01.
    var xor_expected = hex.decode[64](
        "34D04F6C3F3B269DF11F353F35E6DFD2"
        + "6FEBDA05F52F2350AA4276F356846CBB"
        + "0BB27756B8C3AB08772F508EC8385C52"
        + "05E86D35CDD3F1A85DDF7220842C91C1"
    )
    var ones = InlineArray[UInt8, 64](fill=1)
    var ctr2 = CTR(AesCpu[16](key), iv)
    ctr2.encrypt(ones)
    assert_equal(ones, xor_expected, msg="keystream_xor")

    # `counter_wrap`: NONCE2 starts the BE counter at 0xFFFFFFFE, so the 4-block
    # (64-byte) keystream crosses the 32-bit wrap (..FE, ..FF, 0, 1) without the
    # carry escaping into the nonce.
    var iv2 = hex.decode[16]("222222222222222222222222FFFFFFFE")
    var wrap_expected = hex.decode[64](
        "58FC849D1CF53C54C63E1B1D15CB3C8A"
        + "AA335F72135585E9FF943F4DAC77CB63"
        + "BD1AE8716BE69C3B4D886B222B9B4E1E"
        + "67548EF896A96E2746D8CA6476D8B183"
    )
    var wrap = InlineArray[UInt8, 64](fill=0)
    var ctr3 = CTR(AesCpu[16](key), iv2)
    ctr3.encrypt(wrap)
    assert_equal(wrap, wrap_expected, msg="counter_wrap")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
