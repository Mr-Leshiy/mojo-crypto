from std.testing import TestSuite, assert_equal

from mojo_crypto.macs import Hmac
from mojo_crypto.utils.hex import hex_decode, hex_encode

from tests.hashes.utils import (
    DigestEngine,
    run_sha224_checks,
    run_sha256_checks,
    run_sha384_checks,
    run_sha512_checks,
)


@fieldwise_init
struct CheckInput(Copyable, Movable):
    """A single (key, message, tag) triple, for one digest."""

    var key_hex: String
    var data_hex: String
    var expected_hex: String
    """
    The expected tag. Compared against only as many leading tag bytes as it
    carries — RFC 4231 Test Case 5 pins just the first 128 bits.
    """


@fieldwise_init
struct Rfc4231Case(Copyable, Movable):
    """One RFC 4231 §4 test case: one key and message, four expected tags."""

    var key_hex: String
    var data_hex: String
    var sha224_hex: String
    var sha256_hex: String
    var sha384_hex: String
    var sha512_hex: String


def _assert_tag[
    SIZE: Int
](tag: Array[UInt8, SIZE], expected_hex: String) raises:
    var expected_len = expected_hex.byte_length() // 2
    assert_equal(hex_encode(Span(tag)[:expected_len]), expected_hex)


@__parameter
def check_hmac[T: DigestEngine](input: CheckInput) raises:
    """
    Reach the same tag by three routes, all of which must agree with the vector.
    """
    var key = hex_decode(input.key_hex)
    var data = hex_decode(input.data_hex)

    # One-shot: the whole message in a single `update`.
    var one_shot = Hmac[T](Span(key))
    one_shot.update(Span(data))
    _assert_tag(one_shot^.finalize(), input.expected_hex)

    # Streamed one byte per `update` call, which exercises the inner hash's
    # block buffering across `update` boundaries — untouched by the one-shot
    # path.
    var streamed = Hmac[T](Span(key))
    for i in range(len(data)):
        streamed.update(Span(data)[i : i + 1])
    _assert_tag(streamed^.finalize(), input.expected_hex)

    # Preceded by a decoy message and a `reset`, which must restore the inner
    # hash to the ipad state and keep the key.
    var after_reset = Hmac[T](Span(key))
    after_reset.update("discarded".as_bytes())
    after_reset.reset()
    after_reset.update(Span(data))
    _assert_tag(after_reset^.finalize(), input.expected_hex)


def _run_rfc4231_case(vector: Rfc4231Case) raises:
    """Check the case's four digests, on every backend available."""
    run_sha224_checks[check_hmac](
        CheckInput(vector.key_hex, vector.data_hex, vector.sha224_hex)
    )
    run_sha256_checks[check_hmac](
        CheckInput(vector.key_hex, vector.data_hex, vector.sha256_hex)
    )
    run_sha384_checks[check_hmac](
        CheckInput(vector.key_hex, vector.data_hex, vector.sha384_hex)
    )
    run_sha512_checks[check_hmac](
        CheckInput(vector.key_hex, vector.data_hex, vector.sha512_hex)
    )


# Test vectors from RFC 4231 Section 4 (HMAC-SHA-224/256/384/512):
# https://datatracker.ietf.org/doc/html/rfc4231#section-4


def _case_1() -> Rfc4231Case:
    """§4.2 — 20-byte key, 8-byte message ("Hi There")."""
    return Rfc4231Case(
        key_hex=String("0b" * 20),
        data_hex="4869205468657265",
        sha224_hex="896fb1128abbdf196832107cd49df33f"
        + "47b4b1169912ba4f53684b22",
        sha256_hex="b0344c61d8db38535ca8afceaf0bf12b"
        + "881dc200c9833da726e9376c2e32cff7",
        sha384_hex="afd03944d84895626b0825f4ab46907f"
        + "15f9dadbe4101ec682aa034c7cebc59c"
        + "faea9ea9076ede7f4af152e8b2fa9cb6",
        sha512_hex="87aa7cdea5ef619d4ff0b4241a1d6cb0"
        + "2379f4e2ce4ec2787ad0b30545e17cde"
        + "daa833b7d6b8a702038b274eaea3f4e4"
        + "be9d914eeb61f1702e696c203a126854",
    )


def _case_2() -> Rfc4231Case:
    """§4.3 — key shorter than the digest ("Jefe")."""
    return Rfc4231Case(
        key_hex="4a656665",
        # "what do ya want for nothing?"
        data_hex="7768617420646f2079612077616e7420"
        + "666f72206e6f7468696e673f",
        sha224_hex="a30e01098bc6dbbf45690f3a7e9e6d0f"
        + "8bbea2a39e6148008fd05e44",
        sha256_hex="5bdcc146bf60754e6a042426089575c7"
        + "5a003f089d2739839dec58b964ec3843",
        sha384_hex="af45d2e376484031617f78d2b58a6b1b"
        + "9c7ef464f5a01b47e42ec3736322445e"
        + "8e2240ca5e69e2c78b3239ecfab21649",
        sha512_hex="164b7a7bfcf819e2e395fbe73b56e0a3"
        + "87bd64222e831fd610270cd7ea250554"
        + "9758bf75c05a994a6d034f65f8f0e6fd"
        + "caeab1a34d4a6b4b636e070a38bce737",
    )


def _case_3() -> Rfc4231Case:
    """§4.4 — key + data longer than the 64-byte SHA-224/256 block."""
    return Rfc4231Case(
        key_hex=String("aa" * 20),
        data_hex=String("dd" * 50),
        sha224_hex="7fb3cb3588c6c1f6ffa9694d7d6ad264"
        + "9365b0c1f65d69d1ec8333ea",
        sha256_hex="773ea91e36800e46854db8ebd09181a7"
        + "2959098b3ef8c122d9635514ced565fe",
        sha384_hex="88062608d3e6ad8a0aa2ace014c8a86f"
        + "0aa635d947ac9febe83ef4e55966144b"
        + "2a5ab39dc13814b94e3ab6e101a34f27",
        sha512_hex="fa73b0089d56a284efb0f0756c890be9"
        + "b1b5dbdd8ee81a3655f83e33b2279d39"
        + "bf3e848279a722c806b485a47e67c807"
        + "b946a337bee8942674278859e13292fb",
    )


def _case_4() -> Rfc4231Case:
    """§4.5 — 25-byte key, key + data longer than the 64-byte block."""
    return Rfc4231Case(
        key_hex="0102030405060708090a0b0c0d0e0f10" + "111213141516171819",
        data_hex=String("cd" * 50),
        sha224_hex="6c11506874013cac6a2abc1bb382627c"
        + "ec6a90d86efc012de7afec5a",
        sha256_hex="82558a389a443c0ea4cc819899f2083a"
        + "85f0faa3e578f8077a2e3ff46729665b",
        sha384_hex="3e8a69b7783c25851933ab6290af6ca7"
        + "7a9981480850009cc5577c6e1f573b4e"
        + "6801dd23c4a7d679ccf8a386c674cffb",
        sha512_hex="b0ba465637458c6990e5a8c5f61d4af7"
        + "e576d97ff94b872de76f8050361ee3db"
        + "a91ca5c11aa25eb4d679275cc5788063"
        + "a5f19741120c4f2de2adebeb10a298dd",
    )


def _case_5() -> Rfc4231Case:
    """
    §4.6 — output truncated to 128 bits.

    Every expected value here is 16 bytes, so `_assert_tag` compares only the
    tag's leading 128 bits regardless of the digest's own output size.
    """
    return Rfc4231Case(
        key_hex=String("0c" * 20),
        # "Test With Truncation"
        data_hex="546573742057697468205472756e6361" + "74696f6e",
        sha224_hex="0e2aea68a90c8d37c988bcdb9fca6fa8",
        sha256_hex="a3b6167473100ee06e0c796c2955552b",
        sha384_hex="3abf34c3503b2a23a46efc619baef897",
        sha512_hex="415fad6271580a531d4179bc891d87a6",
    )


def _case_6() -> Rfc4231Case:
    """
    §4.7 — 131-byte key, larger than the 128-byte SHA-384/512 block.

    The key must be hashed down before the ipad/opad step.
    """
    return Rfc4231Case(
        key_hex=String("aa" * 131),
        # "Test Using Larger Than Block-Size Key - Hash Key First"
        data_hex="54657374205573696e67204c61726765"
        + "72205468616e20426c6f636b2d53697a"
        + "65204b6579202d2048617368204b6579"
        + "204669727374",
        sha224_hex="95e9a0db962095adaebe9b2d6f0dbce2"
        + "d499f112f2d2b7273fa6870e",
        sha256_hex="60e431591ee0b67f0d8a26aacbf5b77f"
        + "8e0bc6213728c5140546040f0ee37f54",
        sha384_hex="4ece084485813e9088d2c63a041bc5b4"
        + "4f9ef1012a2b588f3cd11f05033ac4c6"
        + "0c2ef6ab4030fe8296248df163f44952",
        sha512_hex="80b24263c7c1a3ebb71493c1dd7be8b4"
        + "9b46d1f41b4aeec1121b013783f8f352"
        + "6b56d037e05f2598bd0fd2215d6a1e52"
        + "95e64f73f63f0aec8b915a985d786598",
    )


def _case_7() -> Rfc4231Case:
    """§4.8 — 131-byte key and 152-byte message, both over the 128-byte block.
    """
    return Rfc4231Case(
        key_hex=String("aa" * 131),
        # "This is a test using a larger than block-size key and a larger
        #  than block-size data. The key needs to be hashed before being
        #  used by the HMAC algorithm."
        data_hex="54686973206973206120746573742075"
        + "73696e672061206c6172676572207468"
        + "616e20626c6f636b2d73697a65206b65"
        + "7920616e642061206c61726765722074"
        + "68616e20626c6f636b2d73697a652064"
        + "6174612e20546865206b6579206e6565"
        + "647320746f2062652068617368656420"
        + "6265666f7265206265696e6720757365"
        + "642062792074686520484d414320616c"
        + "676f726974686d2e",
        sha224_hex="3a854166ac5d9f023f54d517d0b39dbd"
        + "946770db9c2b95c9f6f565d1",
        sha256_hex="9b09ffa71b942fcb27635fbcd5b0e944"
        + "bfdc63644f0713938a7f51535c3a35e2",
        sha384_hex="6617178e941f020d351e2f254e8fd32c"
        + "602420feb0b8fb9adccebb82461e99c5"
        + "a678cc31e799176d3860e6110c46523e",
        sha512_hex="e37b6a775dc87dbaa4dfa9f96e5e3ffd"
        + "debd71f8867289865df5a32d20cdc944"
        + "b6022cac3c4982b10d5eeb55c3e4de15"
        + "134676fb6de0446065c97440fa8c6a58",
    )


def test_rfc4231_vectors() raises:
    _run_rfc4231_case(_case_1())
    _run_rfc4231_case(_case_2())
    _run_rfc4231_case(_case_3())
    _run_rfc4231_case(_case_4())
    _run_rfc4231_case(_case_5())
    _run_rfc4231_case(_case_6())
    _run_rfc4231_case(_case_7())


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
