from std.testing import TestSuite, assert_equal

from mojo_crypto.utils.hex import hex_decode

from tests.hashes.utils import (
    DigestEngine,
    XofEngine,
    run_sha3_224_checks,
    run_sha3_256_checks,
    run_sha3_384_checks,
    run_sha3_512_checks,
    run_shake128_checks,
    run_shake256_checks,
)


@fieldwise_init
struct CheckInput(Copyable, Movable):
    var msg: String
    var expected_hex: String


@parameter
def check_hash[T: DigestEngine](input: CheckInput) raises:
    var h = T()
    h.update(input.msg.as_bytes())
    var out = h^.finalize()
    var expected = hex_decode[T.OUTPUT_SIZE](input.expected_hex)
    assert_equal(out, expected)


@parameter
def check_xof[T: XofEngine, output_len: Int](input: CheckInput) raises:
    var h = T()
    h.update(input.msg.as_bytes())
    var out = h.squeeze[output_len]()
    var expected = hex_decode[output_len](input.expected_hex)
    assert_equal(out, expected)

    h.reset()
    h.update(input.msg.as_bytes())

    # Squeezing the same output in two separate calls must give the same bytes
    # as squeezing it all at once — this is the point of an XOF.
    var first_len = output_len // 2
    var out_2 = List[UInt8](length=output_len, fill=0)
    var expected_2 = hex_decode(input.expected_hex)
    h.squeeze(Span(out_2)[:first_len])
    h.squeeze(Span(out_2)[first_len:])
    assert_equal(out_2, expected_2)


comptime MSG_448 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
comptime MSG_896 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"


# generated:
#   echo -n <msg> | openssl dgst -sha3-224
def test_sha3_224_vectors() raises:
    run_sha3_224_checks[check_hash](
        CheckInput(
            msg="",
            expected_hex=(
                "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
            ),
        )
    )
    run_sha3_224_checks[check_hash](
        CheckInput(
            msg="abc",
            expected_hex=(
                "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"
            ),
        )
    )
    run_sha3_224_checks[check_hash](
        CheckInput(
            msg=MSG_448,
            expected_hex=(
                "8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33"
            ),
        )
    )
    run_sha3_224_checks[check_hash](
        CheckInput(
            msg=MSG_896,
            expected_hex=(
                "543e6868e1666c1a643630df77367ae5a62a85070a51c14cbf665cbc"
            ),
        )
    )
    run_sha3_224_checks[check_hash](
        CheckInput(
            msg=String("a" * 1_000_000),
            expected_hex=(
                "d69335b93325192e516a912e6d19a15cb51c6ed5c15243e7a7fd653c"
            ),
        )
    )


# generated:
#   echo -n <msg> | openssl dgst -sha3-256
def test_sha3_256_vectors() raises:
    run_sha3_256_checks[check_hash](
        CheckInput(
            msg="",
            expected_hex="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        )
    )
    run_sha3_256_checks[check_hash](
        CheckInput(
            msg="abc",
            expected_hex="3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
        )
    )
    run_sha3_256_checks[check_hash](
        CheckInput(
            msg=MSG_448,
            expected_hex="41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376",
        )
    )
    run_sha3_256_checks[check_hash](
        CheckInput(
            msg=MSG_896,
            expected_hex="916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18",
        )
    )
    run_sha3_256_checks[check_hash](
        CheckInput(
            msg=String("a" * 1_000_000),
            expected_hex="5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1",
        )
    )


# generated:
#   echo -n <msg> | openssl dgst -sha3-384
def test_sha3_384_vectors() raises:
    run_sha3_384_checks[check_hash](
        CheckInput(
            msg="",
            expected_hex="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
        )
    )
    run_sha3_384_checks[check_hash](
        CheckInput(
            msg="abc",
            expected_hex="ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25",
        )
    )
    run_sha3_384_checks[check_hash](
        CheckInput(
            msg=MSG_448,
            expected_hex="991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5aa04a1f076e62fea19eef51acd0657c22",
        )
    )
    run_sha3_384_checks[check_hash](
        CheckInput(
            msg=MSG_896,
            expected_hex="79407d3b5916b59c3e30b09822974791c313fb9ecc849e406f23592d04f625dc8c709b98b43b3852b337216179aa7fc7",
        )
    )
    run_sha3_384_checks[check_hash](
        CheckInput(
            msg=String("a" * 1_000_000),
            expected_hex="eee9e24d78c1855337983451df97c8ad9eedf256c6334f8e948d252d5e0e76847aa0774ddb90a842190d2c558b4b8340",
        )
    )


# generated:
#   echo -n <msg> | openssl dgst -sha3-512
def test_sha3_512_vectors() raises:
    run_sha3_512_checks[check_hash](
        CheckInput(
            msg="",
            expected_hex="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
        )
    )
    run_sha3_512_checks[check_hash](
        CheckInput(
            msg="abc",
            expected_hex="b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
        )
    )
    run_sha3_512_checks[check_hash](
        CheckInput(
            msg=MSG_448,
            expected_hex="04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636dee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e",
        )
    )
    run_sha3_512_checks[check_hash](
        CheckInput(
            msg=MSG_896,
            expected_hex="afebb2ef542e6579c50cad06d2e578f9f8dd6881d7dc824d26360feebf18a4fa73e3261122948efcfd492e74e82e2189ed0fb440d187f382270cb455f21dd185",
        )
    )
    run_sha3_512_checks[check_hash](
        CheckInput(
            msg=String("a" * 1_000_000),
            expected_hex="3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859ed311d0a9d5141ce9cc5c66ee689b266a8aa18ace8282a0e0db596c90b0a7b87",
        )
    )


# generated:
#   echo -n <msg> | openssl dgst -shake128 -xoflen <n>
def test_shake128_vectors() raises:
    run_shake128_checks[32, check_xof](
        CheckInput(
            msg="",
            expected_hex="7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
        )
    )
    run_shake128_checks[32, check_xof](
        CheckInput(
            msg="abc",
            expected_hex="5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8",
        )
    )
    run_shake128_checks[32, check_xof](
        CheckInput(
            msg=MSG_448,
            expected_hex="1a96182b50fb8c7e74e0a707788f55e98209b8d91fade8f32f8dd5cff7bf21f5",
        )
    )
    run_shake128_checks[32, check_xof](
        CheckInput(
            msg=String("a" * 1_000_000),
            expected_hex="9d222c79c4ff9d092cf6ca86143aa411e369973808ef97093255826c5572ef58",
        )
    )


# generated:
#   echo -n <msg> | openssl dgst -shake256 -xoflen <n>
def test_shake256_vectors() raises:
    run_shake256_checks[64, check_xof](
        CheckInput(
            msg="",
            expected_hex="46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
        )
    )
    run_shake256_checks[64, check_xof](
        CheckInput(
            msg="abc",
            expected_hex="483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4",
        )
    )
    run_shake256_checks[64, check_xof](
        CheckInput(
            msg=MSG_448,
            expected_hex="4d8c2dd2435a0128eefbb8c36f6f87133a7911e18d979ee1ae6be5d4fd2e332940d8688a4e6a59aa8060f1f9bc996c05aca3c696a8b66279dc672c740bb224ec",
        )
    )
    run_shake256_checks[64, check_xof](
        CheckInput(
            msg=String("a" * 1_000_000),
            expected_hex="3578a7a4ca9137569cdf76ed617d31bb994fca9c1bbf8b184013de8234dfd13a3fd124d4df76c0a539ee7dd2f6e1ec346124c815d9410e145eb561bcd97b18ab",
        )
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
