from std.testing import assert_equal, TestSuite
from std.reflection import reflect
from warp import Runtime

from mojo_crypto.utils import to_array
from mojo_crypto.utils.hex import hex_decode
from mojo_crypto.block_ciphers.modes import CtrMode, GpuCtrMode

from tests.block_ciphers.utils import (
    run_aes_checks,
    run_gpu_aes_checks,
    BlockCipherEngine,
    AsyncBlockCipherEngine,
)

# Width in bytes of the incrementing counter field (CTR-32).
comptime CTR_SIZE: Int = 4


@fieldwise_init
struct CtrTestVector(Copyable, Movable):
    var name: String
    var big_endian: Bool
    var key: List[UInt8]
    var iv: List[UInt8]
    var pt: List[UInt8]
    var ct: List[UInt8]


def check_ctr[
    C: BlockCipherEngine,
    KeySize: Int,
    //,
    cipher_init: def(Array[UInt8, KeySize]) raises capturing[_] -> C,
](vectors: List[CtrTestVector]) raises:
    for v in vectors:
        if len(v.key) != KeySize:
            continue

        var msg = "[CtrMode[{}]], {}".format(reflect[C].name(), v.name)

        var key = to_array[KeySize](v.key)
        var iv = to_array[C.BLOCK_SIZE](v.iv)

        var pt = v.pt.copy()
        var ct = v.ct.copy()
        if v.big_endian:
            comptime CTR = CtrMode[C, CTR_SIZE, BIG_ENDIAN=True]
            var enc = CTR(cipher_init(key), iv.copy())
            enc.encrypt(pt[:])
            var dec = CTR(cipher_init(key), iv^)
            dec.decrypt(ct[:])
        else:
            comptime CTR = CtrMode[C, CTR_SIZE, BIG_ENDIAN=False]
            var enc = CTR(cipher_init(key), iv.copy())
            enc.encrypt(pt[:])
            var dec = CTR(cipher_init(key), iv^)
            dec.decrypt(ct[:])
        assert_equal(pt, v.ct, msg=msg)
        assert_equal(ct, v.pt, msg=msg)


def check_ctr_async[
    C: AsyncBlockCipherEngine,
    KeySize: Int,
    //,
    cipher_init: def(Array[UInt8, KeySize]) raises capturing[_] -> C,
](mut runtime: Runtime, vectors: List[CtrTestVector]) raises:
    for v in vectors:
        if len(v.key) != KeySize:
            continue

        var msg = "[GpuCtrMode[{}]], {}".format(reflect[C].name(), v.name)

        var key = to_array[KeySize](v.key)
        var iv = to_array[C.BLOCK_SIZE](v.iv)

        var pt = v.pt.copy()
        var ct = v.ct.copy()
        if v.big_endian:
            comptime CTR = GpuCtrMode[C, CTR_SIZE, BIG_ENDIAN=True]
            var enc = CTR(cipher_init(key), iv.copy())
            runtime.block_on(enc.encrypt(runtime.context(), pt[:]))
            var dec = CTR(cipher_init(key), iv^)
            runtime.block_on(dec.decrypt(runtime.context(), ct[:]))
        else:
            comptime CTR = GpuCtrMode[C, CTR_SIZE, BIG_ENDIAN=False]
            var enc = CTR(cipher_init(key), iv.copy())
            runtime.block_on(enc.encrypt(runtime.context(), pt[:]))
            var dec = CTR(cipher_init(key), iv^)
            runtime.block_on(dec.decrypt(runtime.context(), ct[:]))
        assert_equal(pt, v.ct, msg=msg)
        assert_equal(ct, v.pt, msg=msg)


# Reference vectors from RustCrypto `block-modes`:
# https://github.com/RustCrypto/block-modes/blob/master/ctr/tests/ctr32/le.rs
# https://github.com/RustCrypto/block-modes/blob/master/ctr/tests/ctr32/be.rs
def ctr32_vectors() raises -> List[CtrTestVector]:
    var key = hex_decode("000102030405060708090A0B0C0D0E0F")
    var zeros = List[UInt8](length=64, fill=0)
    var ones = List[UInt8](length=64, fill=1)
    return [
        # `counter_incr`: encrypting 64 zero bytes yields the raw keystream.
        CtrTestVector(
            name="le counter_incr",
            big_endian=False,
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
            big_endian=False,
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
            big_endian=False,
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
        CtrTestVector(
            name="be counter_incr",
            big_endian=True,
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
            big_endian=True,
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
            big_endian=True,
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


def test_ctr_32_aes() raises:
    run_aes_checks[List[CtrTestVector], check_ctr](ctr32_vectors())


def test_ctr_32_aes_gpu() raises:
    run_gpu_aes_checks[List[CtrTestVector], check_ctr_async](ctr32_vectors())


def main() raises:
    var suite = TestSuite.discover_tests[__functions_in_module()]()
    # TODO: skipped due to https://github.com/modular/modular/issues/7368,
    # restore the `comptime if not has_accelerator()` guard once fixed.
    suite.skip[test_ctr_32_aes_gpu]()
    suite^.run()
