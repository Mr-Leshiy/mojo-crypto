from std.testing import assert_equal, TestSuite

from mojo_crypto.aes import Aes, AesGpu, Sbox
from mojo_crypto.aes.expand import key_expansion
from mojo_crypto.aes.testing_utils import (
    AesKey,
    AesTestVector,
    parse_hex,
    load_aes_vectors,
)


def test_aes_128() raises:
    def check_aes(
        plaintext: InlineArray[UInt8, 16],
        key: InlineArray[UInt8, 16],
        expected: InlineArray[UInt8, 16],
    ) raises:
        var aes = Aes[16](key)
        var enc = aes.encrypt(plaintext)
        assert_equal(enc, expected)
        var dec = aes.decrypt(enc)
        assert_equal(dec, plaintext)

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


def check_key_expansion[
    Nk: Int, WordsSize: Int, KeySize: Int
](
    key: InlineArray[UInt8, KeySize],
    expected: InlineArray[UInt32, WordsSize],
) raises:
    var result = key_expansion[WordsSize, Nk](key)
    assert_equal(expected, result)


def test_128_key_expansion() raises:
    check_key_expansion[Nk=4, WordsSize=44](
        InlineArray[UInt8, 16](fill=0x00),
        [
            # fmt: off
            0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x62636363, 0x62636363, 0x62636363, 0x62636363,
            0x9b9898c9, 0xf9fbfbaa, 0x9b9898c9, 0xf9fbfbaa,
            0x90973450, 0x696ccffa, 0xf2f45733, 0x0b0fac99,
            0xee06da7b, 0x876a1581, 0x759e42b2, 0x7e91ee2b,
            0x7f2e2b88, 0xf8443e09, 0x8dda7cbb, 0xf34b9290,
            0xec614b85, 0x1425758c, 0x99ff0937, 0x6ab49ba7,
            0x21751787, 0x3550620b, 0xacaf6b3c, 0xc61bf09b,
            0x0ef90333, 0x3ba96138, 0x97060a04, 0x511dfa9f,
            0xb1d4d8e2, 0x8a7db9da, 0x1d7bb3de, 0x4c664941,
            0xb4ef5bcb, 0x3e92e211, 0x23e951cf, 0x6f8f188e,
            # fmt: on
        ],
    )

    check_key_expansion[Nk=4, WordsSize=44](
        InlineArray[UInt8, 16](fill=0xFF),
        [
            # fmt: off
            0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
            0xe8e9e9e9, 0x17161616, 0xe8e9e9e9, 0x17161616,
            0xadaeae19, 0xbab8b80f, 0x525151e6, 0x454747f0,
            0x090e2277, 0xb3b69a78, 0xe1e7cb9e, 0xa4a08c6e,
            0xe16abd3e, 0x52dc2746, 0xb33becd8, 0x179b60b6,
            0xe5baf3ce, 0xb766d488, 0x045d3850, 0x13c658e6,
            0x71d07db3, 0xc6b6a93b, 0xc2eb916b, 0xd12dc98d,
            0xe90d208d, 0x2fbb89b6, 0xed5018dd, 0x3c7dd150,
            0x96337366, 0xb988fad0, 0x54d8e20d, 0x68a5335d,
            0x8bf03f23, 0x3278c5f3, 0x66a027fe, 0x0e0514a3,
            0xd60a3588, 0xe472f07b, 0x82d2d785, 0x8cd7c326,
            # fmt: on
        ],
    )

    check_key_expansion[Nk=4, WordsSize=44, KeySize=16](
        [
            # fmt: off
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
            # fmt: on
        ],
        [
            # fmt: off
            0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
            0xd6aa74fd, 0xd2af72fa, 0xdaa678f1, 0xd6ab76fe,
            0xb692cf0b, 0x643dbdf1, 0xbe9bc500, 0x6830b3fe,
            0xb6ff744e, 0xd2c2c9bf, 0x6c590cbf, 0x0469bf41,
            0x47f7f7bc, 0x95353e03, 0xf96c32bc, 0xfd058dfd,
            0x3caaa3e8, 0xa99f9deb, 0x50f3af57, 0xadf622aa,
            0x5e390f7d, 0xf7a69296, 0xa7553dc1, 0x0aa31f6b,
            0x14f9701a, 0xe35fe28c, 0x440adf4d, 0x4ea9c026,
            0x47438735, 0xa41c65b9, 0xe016baf4, 0xaebf7ad2,
            0x549932d1, 0xf0855768, 0x1093ed9c, 0xbe2c974e,
            0x13111d7f, 0xe3944a17, 0xf307a78b, 0x4d2b30c5,
            # fmt: on
        ],
    )

    check_key_expansion[Nk=4, WordsSize=44, KeySize=16](
        [
            # fmt: off
            0x69, 0x20, 0xe2, 0x99, 0xa5, 0x20, 0x2a, 0x6d,
            0x65, 0x6e, 0x63, 0x68, 0x69, 0x74, 0x6f, 0x2a
            # fmt: on
        ],
        [
            # fmt: off
            0x6920e299, 0xa5202a6d, 0x656e6368, 0x69746f2a,
            0xfa880760, 0x5fa82d0d, 0x3ac64e65, 0x53b2214f,
            0xcf75838d, 0x90ddae80, 0xaa1be0e5, 0xf9a9c1aa,
            0x180d2f14, 0x88d08194, 0x22cb6171, 0xdb62a0db,
            0xbaed96ad, 0x323d1739, 0x10f67648, 0xcb94d693,
            0x881b4ab2, 0xba265d8b, 0xaad02bc3, 0x6144fd50,
            0xb34f195d, 0x096944d6, 0xa3b96f15, 0xc2fd9245,
            0xa7007778, 0xae6933ae, 0x0dd05cbb, 0xcf2dcefe,
            0xff8bccf2, 0x51e2ff5c, 0x5c32a3e7, 0x931f6d19,
            0x24b7182e, 0x7555e772, 0x29674495, 0xba78298c,
            0xae127cda, 0xdb479ba8, 0xf220df3d, 0x4858f6b1,
            # fmt: on
        ],
    )

    check_key_expansion[Nk=4, WordsSize=44, KeySize=16](
        [
            # fmt: off
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
            # fmt: on
        ],
        [
            # fmt: off
            0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c,
            0xa0fafe17, 0x88542cb1, 0x23a33939, 0x2a6c7605,
            0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f,
            0x3d80477d, 0x4716fe3e, 0x1e237e44, 0x6d7a883b,
            0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00,
            0xd4d1c6f8, 0x7c839d87, 0xcaf2b8bc, 0x11f915bc,
            0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd,
            0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f,
            0xead27321, 0xb58dbad2, 0x312bf560, 0x7f8d292f,
            0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e,
            0xd014f9a8, 0xc9ee2589, 0xe13f0cc8, 0xb6630ca6,
            # fmt: on
        ],
    )


def test_192_key_expansion() raises:
    check_key_expansion[Nk=6, WordsSize=52](
        InlineArray[UInt8, 24](fill=0x00),
        [
            # fmt: off
            0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x62636363, 0x62636363,
            0x62636363, 0x62636363, 0x62636363, 0x62636363,
            0x9b9898c9, 0xf9fbfbaa, 0x9b9898c9, 0xf9fbfbaa,
            0x9b9898c9, 0xf9fbfbaa, 0x90973450, 0x696ccffa,
            0xf2f45733, 0x0b0fac99, 0x90973450, 0x696ccffa,
            0xc81d19a9, 0xa171d653, 0x53858160, 0x588a2df9,
            0xc81d19a9, 0xa171d653, 0x7bebf49b, 0xda9a22c8,
            0x891fa3a8, 0xd1958e51, 0x198897f8, 0xb8f941ab,
            0xc26896f7, 0x18f2b43f, 0x91ed1797, 0x407899c6,
            0x59f00e3e, 0xe1094f95, 0x83ecbc0f, 0x9b1e0830,
            0x0af31fa7, 0x4a8b8661, 0x137b885f, 0xf272c7ca,
            0x432ac886, 0xd834c0b6, 0xd2c7df11, 0x984c5970,
            # fmt: on
        ],
    )

    check_key_expansion[Nk=6, WordsSize=52](
        InlineArray[UInt8, 24](fill=0xFF),
        [
            # fmt: off
            0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
            0xffffffff, 0xffffffff, 0xe8e9e9e9, 0x17161616,
            0xe8e9e9e9, 0x17161616, 0xe8e9e9e9, 0x17161616,
            0xadaeae19, 0xbab8b80f, 0x525151e6, 0x454747f0,
            0xadaeae19, 0xbab8b80f, 0xc5c2d8ed, 0x7f7a60e2,
            0x2d2b3104, 0x686c76f4, 0xc5c2d8ed, 0x7f7a60e2,
            0x1712403f, 0x686820dd, 0x454311d9, 0x2d2f672d,
            0xe8edbfc0, 0x9797df22, 0x8f8cd3b7, 0xe7e4f36a,
            0xa2a7e2b3, 0x8f88859e, 0x67653a5e, 0xf0f2e57c,
            0x2655c33b, 0xc1b13051, 0x6316d2e2, 0xec9e577c,
            0x8bfb6d22, 0x7b09885e, 0x67919b1a, 0xa620ab4b,
            0xc53679a9, 0x29a82ed5, 0xa25343f7, 0xd95acba9,
            0x598e482f, 0xffaee364, 0x3a989acd, 0x1330b418,
            # fmt: on
        ],
    )

    check_key_expansion[Nk=6, WordsSize=52, KeySize=24](
        [
            # fmt: off
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            # fmt: on
        ],
        [
            # fmt: off
            0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
            0x10111213, 0x14151617, 0x5846f2f9, 0x5c43f4fe,
            0x544afef5, 0x5847f0fa, 0x4856e2e9, 0x5c43f4fe,
            0x40f949b3, 0x1cbabd4d, 0x48f043b8, 0x10b7b342,
            0x58e151ab, 0x04a2a555, 0x7effb541, 0x6245080c,
            0x2ab54bb4, 0x3a02f8f6, 0x62e3a95d, 0x66410c08,
            0xf5018572, 0x97448d7e, 0xbdf1c6ca, 0x87f33e3c,
            0xe5109761, 0x83519b69, 0x34157c9e, 0xa351f1e0,
            0x1ea0372a, 0x99530916, 0x7c439e77, 0xff12051e,
            0xdd7e0e88, 0x7e2fff68, 0x608fc842, 0xf9dcc154,
            0x859f5f23, 0x7a8d5a3d, 0xc0c02952, 0xbeefd63a,
            0xde601e78, 0x27bcdf2c, 0xa223800f, 0xd8aeda32,
            0xa4970a33, 0x1a78dc09, 0xc418c271, 0xe3a41d5d,
            # fmt: on
        ],
    )

    check_key_expansion[Nk=6, WordsSize=52, KeySize=24](
        [
            # fmt: off
            0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
            0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
            0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
            # fmt: on
        ],
        [
            # fmt: off
            0x8e73b0f7, 0xda0e6452, 0xc810f32b, 0x809079e5,
            0x62f8ead2, 0x522c6b7b, 0xfe0c91f7, 0x2402f5a5,
            0xec12068e, 0x6c827f6b, 0x0e7a95b9, 0x5c56fec2,
            0x4db7b4bd, 0x69b54118, 0x85a74796, 0xe92538fd,
            0xe75fad44, 0xbb095386, 0x485af057, 0x21efb14f,
            0xa448f6d9, 0x4d6dce24, 0xaa326360, 0x113b30e6,
            0xa25e7ed5, 0x83b1cf9a, 0x27f93943, 0x6a94f767,
            0xc0a69407, 0xd19da4e1, 0xec1786eb, 0x6fa64971,
            0x485f7032, 0x22cb8755, 0xe26d1352, 0x33f0b7b3,
            0x40beeb28, 0x2f18a259, 0x6747d26b, 0x458c553e,
            0xa7e1466c, 0x9411f1df, 0x821f750a, 0xad07d753,
            0xca400538, 0x8fcc5006, 0x282d166a, 0xbc3ce7b5,
            0xe98ba06f, 0x448c773c, 0x8ecc7204, 0x01002202,
            # fmt: on
        ],
    )


def test_256_key_expansion() raises:
    check_key_expansion[Nk=8, WordsSize=60](
        InlineArray[UInt8, 32](fill=0x00),
        [
            # fmt: off
            0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x62636363, 0x62636363, 0x62636363, 0x62636363,
            0xaafbfbfb, 0xaafbfbfb, 0xaafbfbfb, 0xaafbfbfb,
            0x6f6c6ccf, 0x0d0f0fac, 0x6f6c6ccf, 0x0d0f0fac,
            0x7d8d8d6a, 0xd7767691, 0x7d8d8d6a, 0xd7767691,
            0x5354edc1, 0x5e5be26d, 0x31378ea2, 0x3c38810e,
            0x968a81c1, 0x41fcf750, 0x3c717a3a, 0xeb070cab,
            0x9eaa8f28, 0xc0f16d45, 0xf1c6e3e7, 0xcdfe62e9,
            0x2b312bdf, 0x6acddc8f, 0x56bca6b5, 0xbdbbaa1e,
            0x6406fd52, 0xa4f79017, 0x553173f0, 0x98cf1119,
            0x6dbba90b, 0x07767584, 0x51cad331, 0xec71792f,
            0xe7b0e89c, 0x4347788b, 0x16760b7b, 0x8eb91a62,
            0x74ed0ba1, 0x739b7e25, 0x2251ad14, 0xce20d43b,
            0x10f80a17, 0x53bf729c, 0x45c979e7, 0xcb706385,
            # fmt: on
        ],
    )

    check_key_expansion[Nk=8, WordsSize=60](
        InlineArray[UInt8, 32](fill=0xFF),
        [
            # fmt: off
            0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
            0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
            0xe8e9e9e9, 0x17161616, 0xe8e9e9e9, 0x17161616,
            0x0fb8b8b8, 0xf0474747, 0x0fb8b8b8, 0xf0474747,
            0x4a494965, 0x5d5f5f73, 0xb5b6b69a, 0xa2a0a08c,
            0x355858dc, 0xc51f1f9b, 0xcaa7a723, 0x3ae0e064,
            0xafa80ae5, 0xf2f75596, 0x4741e30c, 0xe5e14380,
            0xeca04211, 0x29bf5d8a, 0xe318faa9, 0xd9f81acd,
            0xe60ab7d0, 0x14fde246, 0x53bc014a, 0xb65d42ca,
            0xa2ec6e65, 0x8b5333ef, 0x684bc946, 0xb1b3d38b,
            0x9b6c8a18, 0x8f91685e, 0xdc2d6914, 0x6a702bde,
            0xa0bd9f78, 0x2beeac97, 0x43a565d1, 0xf216b65a,
            0xfc223491, 0x73b35ccf, 0xaf9e35db, 0xc5ee1e05,
            0x0695ed13, 0x2d7b4184, 0x6ede2455, 0x9cc8920f,
            0x546d424f, 0x27de1e80, 0x88402b5b, 0x4dae355e,
            # fmt: on
        ],
    )

    check_key_expansion[Nk=8, WordsSize=60, KeySize=32](
        [
            # fmt: off
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
            # fmt: on
        ],
        [
            # fmt: off
            0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
            0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f,
            0xa573c29f, 0xa176c498, 0xa97fce93, 0xa572c09c,
            0x1651a8cd, 0x0244beda, 0x1a5da4c1, 0x0640bade,
            0xae87dff0, 0x0ff11b68, 0xa68ed5fb, 0x03fc1567,
            0x6de1f148, 0x6fa54f92, 0x75f8eb53, 0x73b8518d,
            0xc656827f, 0xc9a79917, 0x6f294cec, 0x6cd5598b,
            0x3de23a75, 0x524775e7, 0x27bf9eb4, 0x5407cf39,
            0x0bdc905f, 0xc27b0948, 0xad5245a4, 0xc1871c2f,
            0x45f5a660, 0x17b2d387, 0x300d4d33, 0x640a820a,
            0x7ccff71c, 0xbeb4fe54, 0x13e6bbf0, 0xd261a7df,
            0xf01afafe, 0xe7a82979, 0xd7a5644a, 0xb3afe640,
            0x2541fe71, 0x9bf50025, 0x8813bbd5, 0x5a721c0a,
            0x4e5a6699, 0xa9f24fe0, 0x7e572baa, 0xcdf8cdea,
            0x24fc79cc, 0xbf0979e9, 0x371ac23c, 0x6d68de36,
            # fmt: on
        ],
    )

    check_key_expansion[Nk=8, WordsSize=60, KeySize=32](
        [
            # fmt: off
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
            0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
            0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
            0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
            # fmt: on
        ],
        [
            # fmt: off
            0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781,
            0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4,
            0x9ba35411, 0x8e6925af, 0xa51a8b5f, 0x2067fcde,
            0xa8b09c1a, 0x93d194cd, 0xbe49846e, 0xb75d5b9a,
            0xd59aecb8, 0x5bf3c917, 0xfee94248, 0xde8ebe96,
            0xb5a9328a, 0x2678a647, 0x98312229, 0x2f6c79b3,
            0x812c81ad, 0xdadf48ba, 0x24360af2, 0xfab8b464,
            0x98c5bfc9, 0xbebd198e, 0x268c3ba7, 0x09e04214,
            0x68007bac, 0xb2df3316, 0x96e939e4, 0x6c518d80,
            0xc814e204, 0x76a9fb8a, 0x5025c02d, 0x59c58239,
            0xde136967, 0x6ccc5a71, 0xfa256395, 0x9674ee15,
            0x5886ca5d, 0x2e2f31d7, 0x7e0af1fa, 0x27cf73c3,
            0x749c47ab, 0x18501dda, 0xe2757e4f, 0x7401905a,
            0xcafaaae3, 0xe4d59b34, 0x9adf6ace, 0xbd10190d,
            0xfe4890d1, 0xe6188d0b, 0x046df344, 0x706c631e,
            # fmt: on
        ],
    )


# AES Known Answer Test (KAT) Vectors
# https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers#TDES
# https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/KAT_AES.zip
# TODO: refactor once some Cipher trait is available.
def test_aes_cpu_kat() raises:
    var vectors = load_aes_vectors("tests/aes/KAT_AES", "ECB")

    for v in vectors:
        var msg = v.file_name

        if v.key.isa[InlineArray[UInt8, 16]]():
            var aes = Aes[16](v.key[InlineArray[UInt8, 16]])
            assert_equal(aes.encrypt(v.pt), v.ct, msg=msg)
            assert_equal(aes.decrypt(v.ct), v.pt, msg=msg)
        elif v.key.isa[InlineArray[UInt8, 24]]():
            var aes = Aes[24](v.key[InlineArray[UInt8, 24]])
            assert_equal(aes.encrypt(v.pt), v.ct, msg=msg)
            assert_equal(aes.decrypt(v.ct), v.pt, msg=msg)
        else:
            var aes = Aes[32](v.key[InlineArray[UInt8, 32]])
            assert_equal(aes.encrypt(v.pt), v.ct, msg=msg)
            assert_equal(aes.decrypt(v.ct), v.pt, msg=msg)


# AES Known Answer Test (KAT) Vectors
# https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers#TDES
# https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/KAT_AES.zip
# TODO: refactor once some Cipher trait is available.
def test_aes_gpu_kat() raises:
    var vectors = load_aes_vectors("tests/aes/KAT_AES", "ECB")

    for v in vectors:
        var msg = v.file_name

        if v.key.isa[InlineArray[UInt8, 16]]():
            var aes = AesGpu[16](v.key[InlineArray[UInt8, 16]])
            assert_equal(aes.encrypt(v.pt), v.ct, msg=msg)
            assert_equal(aes.decrypt(v.ct), v.pt, msg=msg)
        elif v.key.isa[InlineArray[UInt8, 24]]():
            var aes = AesGpu[24](v.key[InlineArray[UInt8, 24]])
            assert_equal(aes.encrypt(v.pt), v.ct, msg=msg)
            assert_equal(aes.decrypt(v.ct), v.pt, msg=msg)
        else:
            var aes = AesGpu[32](v.key[InlineArray[UInt8, 32]])
            assert_equal(aes.encrypt(v.pt), v.ct, msg=msg)
            assert_equal(aes.decrypt(v.ct), v.pt, msg=msg)


# AES Monte Carlo Test (MCT) Sample Vectors
# https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers#TDES
# https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/aesmct.zip
# TODO: refactor once some Cipher trait is available.
def test_aes_cpu_mct() raises:
    # Number of inner iterations per MCT outer loop, as specified in AESAVS section 6.4.1:
    # https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf
    comptime MCT_INNER_ITERATIONS = 1000

    var vectors = load_aes_vectors("tests/aes/aesmct", "ECB")

    for v in vectors:
        var msg = v.file_name
        if v.key.isa[InlineArray[UInt8, 16]]():
            var aes = Aes[16](v.key[InlineArray[UInt8, 16]])
            var block = v.pt if v.is_encrypt else v.ct
            for _ in range(MCT_INNER_ITERATIONS):
                block = aes.encrypt(block) if v.is_encrypt else aes.decrypt(
                    block
                )
            assert_equal(block, v.ct if v.is_encrypt else v.pt, msg=msg)
        elif v.key.isa[InlineArray[UInt8, 24]]():
            var aes = Aes[24](v.key[InlineArray[UInt8, 24]])
            var block = v.pt if v.is_encrypt else v.ct
            for _ in range(MCT_INNER_ITERATIONS):
                block = aes.encrypt(block) if v.is_encrypt else aes.decrypt(
                    block
                )
            assert_equal(block, v.ct if v.is_encrypt else v.pt, msg=msg)
        else:
            var aes = Aes[32](v.key[InlineArray[UInt8, 32]])
            var block = v.pt if v.is_encrypt else v.ct
            for _ in range(MCT_INNER_ITERATIONS):
                block = aes.encrypt(block) if v.is_encrypt else aes.decrypt(
                    block
                )
            assert_equal(block, v.ct if v.is_encrypt else v.pt, msg=msg)


# AES Monte Carlo Test (MCT) Sample Vectors
# https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers#TDES
# https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/aesmct.zip
# TODO: refactor once some Cipher trait is available.
def test_aes_gpu_mct() raises:
    # Number of inner iterations per MCT outer loop, as specified in AESAVS section 6.4.1:
    # https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf
    comptime MCT_INNER_ITERATIONS = 1000

    var vectors = load_aes_vectors("tests/aes/aesmct", "ECB")

    for v in vectors:
        var msg = v.file_name
        if v.key.isa[InlineArray[UInt8, 16]]():
            var aes = AesGpu[16](v.key[InlineArray[UInt8, 16]])
            var block = v.pt if v.is_encrypt else v.ct
            for _ in range(MCT_INNER_ITERATIONS):
                block = aes.encrypt(block) if v.is_encrypt else aes.decrypt(
                    block
                )
            assert_equal(block, v.ct if v.is_encrypt else v.pt, msg=msg)
        elif v.key.isa[InlineArray[UInt8, 24]]():
            var aes = AesGpu[24](v.key[InlineArray[UInt8, 24]])
            var block = v.pt if v.is_encrypt else v.ct
            for _ in range(MCT_INNER_ITERATIONS):
                block = aes.encrypt(block) if v.is_encrypt else aes.decrypt(
                    block
                )
            assert_equal(block, v.ct if v.is_encrypt else v.pt, msg=msg)
        else:
            var aes = AesGpu[32](v.key[InlineArray[UInt8, 32]])
            var block = v.pt if v.is_encrypt else v.ct
            for _ in range(MCT_INNER_ITERATIONS):
                block = aes.encrypt(block) if v.is_encrypt else aes.decrypt(
                    block
                )
            assert_equal(block, v.ct if v.is_encrypt else v.pt, msg=msg)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
