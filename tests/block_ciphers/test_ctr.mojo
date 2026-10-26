from std.testing import assert_equal, TestSuite
from std.reflection import reflect
from max.gpu.host import DeviceContext

from mojo_crypto.utils import to_array
from mojo_crypto.utils.hex import hex_decode
from mojo_crypto.block_ciphers.modes import CtrMode

from tests.block_ciphers.utils import (
    AesFactory,
    AesAarch64Factory,
    AesGpuFactory,
    AesNaiveFactory,
    AesX86Factory,
    HAS_AES_AARCH64,
    HAS_AES_GPU,
    HAS_AES_X86,
)

# Width in bytes of the incrementing counter field (CTR-32).
comptime CTR_SIZE: Int = 4


@fieldwise_init
struct CtrTestVector(Copyable, Movable):
    var name: String
    var key: List[UInt8]
    var iv: List[UInt8]
    var pt: List[UInt8]
    var ct: List[UInt8]


def check_ctr[
    F: AesFactory, //, BIG_ENDIAN: Bool
](factory: F, vectors: List[CtrTestVector]) raises:
    comptime CTR = CtrMode[F.Cipher, CTR_SIZE, BIG_ENDIAN=BIG_ENDIAN]
    for v in vectors:
        var msg = "[CtrMode[{}]], {}".format(reflect[F.Cipher].name(), v.name)

        var key = to_array[F.KEY_SIZE](v.key)
        var iv = to_array[F.Cipher.BLOCK_SIZE](v.iv)

        var pt = v.pt.copy()
        var enc = CTR(factory.create(key), iv.copy())
        enc.encrypt(pt[:])
        assert_equal(pt, v.ct, msg=msg)

        var ct = v.ct.copy()
        var dec = CTR(factory.create(key), iv^)
        dec.decrypt(ct[:])
        assert_equal(ct, v.pt, msg=msg)


# Reference vectors from RustCrypto `block-modes`:
# https://github.com/RustCrypto/block-modes/blob/master/ctr/tests/ctr32/le.rs
def ctr32_le_aes128_vectors() raises -> List[CtrTestVector]:
    var key = hex_decode("000102030405060708090A0B0C0D0E0F")
    var zeros = List[UInt8](length=64, fill=0)
    var ones = List[UInt8](length=64, fill=1)
    return [
        # `counter_incr`: encrypting 64 zero bytes yields the raw keystream.
        CtrTestVector(
            name="le counter_incr",
            key=key.copy(),
            iv=hex_decode("11111111111111111111111111111191"),
            pt=zeros.copy(),
            ct=hex_decode(
                "2A0680B210CAD45E886D7EF6DAB357C9"
                + "F18B39AFF6930FDB2D9FCE34261FF699"
                + "EB96774669D24B560C9AD028C5C39C45"
                + "80775A82065256B4787DC91C6942B700"
            ),
        ),
        # `keystream_xor`: encrypting 64 bytes of 0x01 yields keystream XOR 0x01.
        CtrTestVector(
            name="le keystream_xor",
            key=key.copy(),
            iv=hex_decode("11111111111111111111111111111191"),
            pt=ones.copy(),
            ct=hex_decode(
                "2B0781B311CBD55F896C7FF7DBB256C8"
                + "F08A38AEF7920EDA2C9ECF35271EF798"
                + "EA97764768D34A570D9BD129C4C29D44"
                + "81765B83075357B5797CC81D6843B601"
            ),
        ),
        # `counter_wrap`: NONCE2 starts the LE counter at 0xFFFFFFFE, so the
        # 4-block (64-byte) keystream crosses the 32-bit wrap (..FE, ..FF, 0, 1)
        # without the carry escaping into the nonce.
        CtrTestVector(
            name="le counter_wrap",
            key=key.copy(),
            iv=hex_decode("FEFFFFFF2222222222222222222222A2"),
            pt=zeros.copy(),
            ct=hex_decode(
                "A1E649D8B382293DC28375C42443BB6A"
                + "226BAADC9E9CCA8214F56E07A4024E06"
                + "6355A0DA2E08FB00112FFA38C26189EE"
                + "55DD5B0B130ED87096FE01B59A665A60"
            ),
        ),
    ]


# Reference vectors from RustCrypto `block-modes`:
# https://github.com/RustCrypto/block-modes/blob/master/ctr/tests/ctr32/be.rs
def ctr32_be_aes128_vectors() raises -> List[CtrTestVector]:
    var key = hex_decode("000102030405060708090A0B0C0D0E0F")
    var zeros = List[UInt8](length=64, fill=0)
    var ones = List[UInt8](length=64, fill=1)
    return [
        CtrTestVector(
            name="be counter_incr",
            key=key.copy(),
            iv=hex_decode("11111111111111111111111111111111"),
            pt=zeros.copy(),
            ct=hex_decode(
                "35D14E6D3E3A279CF01E343E34E7DED3"
                + "6EEADB04F42E2251AB4377F257856DBA"
                + "0AB37657B9C2AA09762E518FC9395D53"
                + "04E96C34CCD2F0A95CDE7321852D90C0"
            ),
        ),
        CtrTestVector(
            name="be keystream_xor",
            key=key.copy(),
            iv=hex_decode("11111111111111111111111111111111"),
            pt=ones.copy(),
            ct=hex_decode(
                "34D04F6C3F3B269DF11F353F35E6DFD2"
                + "6FEBDA05F52F2350AA4276F356846CBB"
                + "0BB27756B8C3AB08772F508EC8385C52"
                + "05E86D35CDD3F1A85DDF7220842C91C1"
            ),
        ),
        # `counter_wrap`: NONCE2 starts the BE counter at 0xFFFFFFFE.
        CtrTestVector(
            name="be counter_wrap",
            key=key.copy(),
            iv=hex_decode("222222222222222222222222FFFFFFFE"),
            pt=zeros.copy(),
            ct=hex_decode(
                "58FC849D1CF53C54C63E1B1D15CB3C8A"
                + "AA335F72135585E9FF943F4DAC77CB63"
                + "BD1AE8716BE69C3B4D886B222B9B4E1E"
                + "67548EF896A96E2746D8CA6476D8B183"
            ),
        ),
    ]


def test_ctr32_le_aes128_naive() raises:
    check_ctr[BIG_ENDIAN=False](
        AesNaiveFactory[16](), ctr32_le_aes128_vectors()
    )


def test_ctr32_be_aes128_naive() raises:
    check_ctr[BIG_ENDIAN=True](AesNaiveFactory[16](), ctr32_be_aes128_vectors())


def test_ctr32_le_aes128_aarch64() raises:
    check_ctr[BIG_ENDIAN=False](
        AesAarch64Factory[16](), ctr32_le_aes128_vectors()
    )


def test_ctr32_be_aes128_aarch64() raises:
    check_ctr[BIG_ENDIAN=True](
        AesAarch64Factory[16](), ctr32_be_aes128_vectors()
    )


def test_ctr32_le_aes128_x86() raises:
    check_ctr[BIG_ENDIAN=False](AesX86Factory[16](), ctr32_le_aes128_vectors())


def test_ctr32_be_aes128_x86() raises:
    check_ctr[BIG_ENDIAN=True](AesX86Factory[16](), ctr32_be_aes128_vectors())


def test_ctr32_le_aes128_gpu() raises:
    with DeviceContext() as ctx:
        check_ctr[BIG_ENDIAN=False](
            AesGpuFactory[16](ctx), ctr32_le_aes128_vectors()
        )


def test_ctr32_be_aes128_gpu() raises:
    with DeviceContext() as ctx:
        check_ctr[BIG_ENDIAN=True](
            AesGpuFactory[16](ctx), ctr32_be_aes128_vectors()
        )


def main() raises:
    var suite = TestSuite()

    suite.test[test_ctr32_le_aes128_naive]()
    suite.test[test_ctr32_be_aes128_naive]()

    comptime if HAS_AES_AARCH64:
        suite.test[test_ctr32_le_aes128_aarch64]()
        suite.test[test_ctr32_be_aes128_aarch64]()

    comptime if HAS_AES_X86:
        suite.test[test_ctr32_le_aes128_x86]()
        suite.test[test_ctr32_be_aes128_x86]()

    comptime if HAS_AES_GPU:
        suite.test[test_ctr32_le_aes128_gpu]()
        suite.test[test_ctr32_be_aes128_gpu]()

    suite^.run()
