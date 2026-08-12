from std.math import min
from std.testing import assert_equal, TestSuite
from std.python import PythonObject
from std.reflection import reflect

from mojo_crypto.utils.hex import hex_decode
from mojo_crypto.utils import to_array, to_list

from tests.acvp.utils import load_python_acvp_vectors
from tests.hashes.utils import (
    DigestEngine,
    run_sha224_checks,
    run_sha256_checks,
    run_sha384_checks,
    run_sha512_checks,
    run_sha512_224_checks,
    run_sha512_256_checks,
)


@fieldwise_init
struct HashTestVector(Copyable, Movable):
    var count: Int
    var msg: List[UInt8]
    var digest: List[UInt8]


def parse_acvp_sha2_aft(
    python_vectors: PythonObject,
) raises -> List[HashTestVector]:
    var vectors = List[HashTestVector]()
    for v in python_vectors:
        var test = v["test"]
        var expected = v["expected"]

        # ACVP allows bit-granular message lengths for SHA-224/384/512-224
        # (registration messageLength increment=1), but Digest.update only
        # ever consumes whole bytes, so there's no way to feed a message
        # ending mid-byte; skip those vectors rather than silently
        # truncating/rounding them.
        if Int(py=test["len"]) % 8 != 0:
            continue

        vectors.append(
            HashTestVector(
                count=Int(py=test["tcId"]),
                msg=hex_decode(String(test["msg"])),
                digest=hex_decode(String(expected["md"])),
            )
        )
    return vectors^


@fieldwise_init
struct MctTestVector(Copyable, Movable):
    var count: Int
    var seed: List[UInt8]
    # 100 chained checkpoint digests; see check_sha2_mct.
    var checkpoints: List[List[UInt8]]
    # Selects the "standard" vs "alternate" chaining rule; see check_sha2_mct.
    var is_alternate: Bool


def parse_acvp_sha2_mct(
    python_vectors: PythonObject,
) raises -> List[MctTestVector]:
    var vectors = List[MctTestVector]()
    for v in python_vectors:
        var group = v["group"]
        var test = v["test"]
        var expected = v["expected"]

        var checkpoints = List[List[UInt8]]()
        for entry in expected["resultsArray"]:
            checkpoints.append(hex_decode(String(entry["md"])))

        vectors.append(
            MctTestVector(
                count=Int(py=test["tcId"]),
                seed=hex_decode(String(test["msg"])),
                checkpoints=checkpoints^,
                is_alternate=String(group["mctVersion"]) == "alternate",
            )
        )
    return vectors^


@parameter
def check_sha2_aft[T: DigestEngine](vectors: List[HashTestVector]) raises:
    for v in vectors:
        var msg = "[{}], count={}".format(reflect[T].name(), v.count)

        var h = T()
        h.update(v.msg[:])
        var actual = h^.finalize()

        var expected = to_array[T.OUTPUT_SIZE](v.digest)
        assert_equal(actual, expected, msg=msg)


# https://github.com/usnistgov/ACVP/blob/master/src/sha/sections/04-testtypes.adoc
#   For j = 0 to 99:
#     A = B = C = SEED
#     For i = 0 to 999:
#       MSG = A || B || C
#       "standard": hash MSG as-is (SEED is exactly one digest wide, so MSG
#         is always 3 digests wide — no truncation/padding needed).
#       "alternate": truncate MSG to the leftmost INITIAL_SEED_LEN bytes, or
#         zero-pad up to it if shorter (SEED may be any supported message
#         length here, e.g. SHA-256/512/512-256 whose registration only
#         allows byte-granular lengths >= 1720 bits).
#       MD = SHA(MSG); A = B; B = C; C = MD
#     Output MD (checkpoint j); SEED = MD
@parameter
def check_sha2_mct[T: DigestEngine](vectors: List[MctTestVector]) raises:
    for v in vectors:
        var msg = "[{}], count={}".format(reflect[T].name(), v.count)
        var initial_len = len(v.seed)

        var seed = v.seed.copy()
        for j in range(len(v.checkpoints)):
            var a = seed.copy()
            var b = seed.copy()
            var c = seed.copy()

            for _ in range(1000):
                var target_len = initial_len if v.is_alternate else (
                    len(a) + len(b) + len(c)
                )
                var buf = List[UInt8](capacity=target_len)

                var take_a = min(len(a), target_len)
                for i in range(take_a):
                    buf.append(a[i])

                var take_b = min(len(b), target_len - len(buf))
                for i in range(take_b):
                    buf.append(b[i])

                var take_c = min(len(c), target_len - len(buf))
                for i in range(take_c):
                    buf.append(c[i])

                for _ in range(target_len - len(buf)):
                    buf.append(0)

                var h = T()
                h.update(buf[:])
                var md = to_list(h^.finalize())

                a = b^
                b = c^
                c = md^

            assert_equal(
                c, v.checkpoints[j], msg="{}, checkpoint={}".format(msg, j)
            )
            seed = c.copy()


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/SHA2-224-1.0
def test_sha224_aft() raises:
    var raw = load_python_acvp_vectors("tests/acvp/data/SHA2-224-1.0", "AFT")
    run_sha224_checks[check_sha2_aft](parse_acvp_sha2_aft(raw))


def test_sha224_mct() raises:
    var raw = load_python_acvp_vectors("tests/acvp/data/SHA2-224-1.0", "MCT")
    run_sha224_checks[check_sha2_mct](parse_acvp_sha2_mct(raw))


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/SHA2-256-1.0
def test_sha256_aft() raises:
    var raw = load_python_acvp_vectors("tests/acvp/data/SHA2-256-1.0", "AFT")
    run_sha256_checks[check_sha2_aft](parse_acvp_sha2_aft(raw))


def test_sha256_mct() raises:
    var raw = load_python_acvp_vectors("tests/acvp/data/SHA2-256-1.0", "MCT")
    run_sha256_checks[check_sha2_mct](parse_acvp_sha2_mct(raw))


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/SHA2-384-1.0
def test_sha384_aft() raises:
    var raw = load_python_acvp_vectors("tests/acvp/data/SHA2-384-1.0", "AFT")
    run_sha384_checks[check_sha2_aft](parse_acvp_sha2_aft(raw))


def test_sha384_mct() raises:
    var raw = load_python_acvp_vectors("tests/acvp/data/SHA2-384-1.0", "MCT")
    run_sha384_checks[check_sha2_mct](parse_acvp_sha2_mct(raw))


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/SHA2-512-1.0
def test_sha512_aft() raises:
    var raw = load_python_acvp_vectors("tests/acvp/data/SHA2-512-1.0", "AFT")
    run_sha512_checks[check_sha2_aft](parse_acvp_sha2_aft(raw))


def test_sha512_mct() raises:
    var raw = load_python_acvp_vectors("tests/acvp/data/SHA2-512-1.0", "MCT")
    run_sha512_checks[check_sha2_mct](parse_acvp_sha2_mct(raw))


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/SHA2-512-224-1.0
def test_sha512_224_aft() raises:
    var raw = load_python_acvp_vectors(
        "tests/acvp/data/SHA2-512-224-1.0", "AFT"
    )
    run_sha512_224_checks[check_sha2_aft](parse_acvp_sha2_aft(raw))


def test_sha512_224_mct() raises:
    var raw = load_python_acvp_vectors(
        "tests/acvp/data/SHA2-512-224-1.0", "MCT"
    )
    run_sha512_224_checks[check_sha2_mct](parse_acvp_sha2_mct(raw))


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/SHA2-512-256-1.0
def test_sha512_256_aft() raises:
    var raw = load_python_acvp_vectors(
        "tests/acvp/data/SHA2-512-256-1.0", "AFT"
    )
    run_sha512_256_checks[check_sha2_aft](parse_acvp_sha2_aft(raw))


def test_sha512_256_mct() raises:
    var raw = load_python_acvp_vectors(
        "tests/acvp/data/SHA2-512-256-1.0", "MCT"
    )
    run_sha512_256_checks[check_sha2_mct](parse_acvp_sha2_mct(raw))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
