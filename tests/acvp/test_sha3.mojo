from std.math import min
from std.testing import assert_equal, TestSuite
from std.python import PythonObject
from std.reflection import reflect

from mojo_crypto.utils.hex import hex_decode
from mojo_crypto.utils import to_list

from tests.acvp.utils import load_python_acvp_vectors
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
struct HashTestVector(Copyable, Movable):
    var count: Int
    var msg: List[UInt8]
    var digest: List[UInt8]


def parse_acvp_sha3_aft(
    python_vectors: PythonObject,
) raises -> List[HashTestVector]:
    var vectors = List[HashTestVector]()
    for v in python_vectors:
        var test = v["test"]
        var expected = v["expected"]

        # SHA3-*-2.0 allows bit-granular messageLength (increment=1), same as
        # the SHA-2 sets, but Digest.update only ever consumes whole bytes;
        # skip vectors that don't end on a byte boundary rather than
        # silently truncating/rounding them.
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
    # 100 chained checkpoint digests; see check_sha3_mct.
    var checkpoints: List[List[UInt8]]
    # Selects the "standard" vs "alternate" chaining rule; see check_sha3_mct.
    var is_alternate: Bool


def parse_acvp_sha3_mct(
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
def check_sha3_aft[T: DigestEngine](vectors: List[HashTestVector]) raises:
    for v in vectors:
        var msg = "[{}], count={}".format(reflect[T].name(), v.count)

        var h = T()
        h.update(v.msg[:])
        var actual = h^.finalize()

        assert_equal(to_list(actual), v.digest, msg=msg)


# https://github.com/usnistgov/ACVP/blob/master/src/sha3/sections/04-testtypes.adoc
#   MD[0] = SEED
#   For j = 0 to 99:
#     For i = 1 to 1000:
#       "standard": MSG = MD[i-1]
#       "alternate": MSG = MD[i-1] truncated to the leftmost INITIAL_SEED_LEN
#         bytes, or zero-padded up to it if shorter
#       MD[i] = SHA3(MSG)
#     Output MD[1000] (checkpoint j); SEED = MD[1000]
# Unlike the SHA-2 CAVS-style MCT, each round hashes the single previous
# digest rather than an A||B||C concatenation. For fixed-output SHA-3, a
# digest is always exactly one seed-width wide, so "standard" and
# "alternate" behave identically in practice — the normalization is a
# no-op — but both are implemented since the registration allows either.
@parameter
def check_sha3_mct[T: DigestEngine](vectors: List[MctTestVector]) raises:
    for v in vectors:
        var msg = "[{}], count={}".format(reflect[T].name(), v.count)
        var initial_len = len(v.seed)

        var md = v.seed.copy()
        for j in range(len(v.checkpoints)):
            for _ in range(1000):
                var input = md.copy()
                if v.is_alternate:
                    input = List[UInt8](capacity=initial_len)
                    var take = min(len(md), initial_len)
                    for i in range(take):
                        input.append(md[i])
                    for _ in range(initial_len - take):
                        input.append(0)

                var h = T()
                h.update(input[:])
                md = to_list(h^.finalize())

            assert_equal(
                md, v.checkpoints[j], msg="{}, checkpoint={}".format(msg, j)
            )


@fieldwise_init
struct XofTestVector(Copyable, Movable):
    var count: Int
    var msg: List[UInt8]
    # In bytes; see parse_acvp_shake_test.
    var out_len: Int
    var digest: List[UInt8]


# Shared by SHAKE's AFT and VOT groups: both are independent-vector tests
# with the same `msg`/`len`/`outLen` shape, VOT just varies `outLen` across
# vectors instead of holding it fixed.
def parse_acvp_shake_test(
    python_vectors: PythonObject,
) raises -> List[XofTestVector]:
    var vectors = List[XofTestVector]()
    for v in python_vectors:
        var test = v["test"]
        var expected = v["expected"]

        # SHAKE-*-1.0 allows bit-granular messageLength *and* outputLen
        # (increment=1 for both, per its registration.json); Xof.update and
        # squeeze only ever consume/produce whole bytes, so skip vectors
        # that don't end on a byte boundary for either. SHAKE-*-FIPS202
        # pins both to increments of 8, so nothing is skipped there.
        if Int(py=test["len"]) % 8 != 0:
            continue
        var out_len_bits = Int(py=test["outLen"])
        if out_len_bits % 8 != 0:
            continue

        vectors.append(
            XofTestVector(
                count=Int(py=test["tcId"]),
                msg=hex_decode(String(test["msg"])),
                out_len=out_len_bits // 8,
                digest=hex_decode(String(expected["md"])),
            )
        )
    return vectors^


@fieldwise_init
struct ShakeMctTestVector(Copyable, Movable):
    var count: Int
    var seed: List[UInt8]
    var min_bytes: Int
    var max_bytes: Int
    # 100 chained checkpoints, each its own length; see check_shake_mct.
    var checkpoints: List[List[UInt8]]


def parse_acvp_shake_mct(
    python_vectors: PythonObject,
) raises -> List[ShakeMctTestVector]:
    var vectors = List[ShakeMctTestVector]()
    for v in python_vectors:
        var group = v["group"]
        var test = v["test"]
        var expected = v["expected"]

        var checkpoints = List[List[UInt8]]()
        for entry in expected["resultsArray"]:
            checkpoints.append(hex_decode(String(entry["md"])))

        vectors.append(
            ShakeMctTestVector(
                count=Int(py=test["tcId"]),
                seed=hex_decode(String(test["msg"])),
                min_bytes=Int(py=group["minOutLen"]) // 8,
                max_bytes=Int(py=group["maxOutLen"]) // 8,
                checkpoints=checkpoints^,
            )
        )
    return vectors^


@parameter
def check_shake_test[T: XofEngine](vectors: List[XofTestVector]) raises:
    for v in vectors:
        var msg = "[{}], count={}".format(reflect[T].name(), v.count)

        var h = T()
        h.update(v.msg[:])
        var out = List[UInt8](length=v.out_len, fill=0)
        h.squeeze(Span(out))

        assert_equal(out, v.digest, msg=msg)


# https://github.com/usnistgov/ACVP/blob/master/src/sha3/sections/04-testtypes.adoc
# Verified against the downloaded SHAKE-128-1.0 vectors (tcId 1393) by
# replaying the recurrence with openssl before writing this — the pseudocode
# alone is easy to misread on ordering:
#   Range = maxOutBytes - minOutBytes + 1
#   OutputLen = maxOutBytes    (set once; persists across the whole test —
#                                not reset at the top of each outer round)
#   MD[0] = SEED
#   For j = 0 to 99:
#     For i = 1 to 1000:
#       MSG = leftmost 128 bits of MD[i-1], zero-padded on the right if
#         MD[i-1] is shorter than that
#       MD[i] = SHAKE(MSG, OutputLen * 8)
#       OutputLen = minOutBytes + (rightmost 16 bits of MD[i], as a
#         big-endian integer, mod Range)
#     Output MD[1000] (checkpoint j); SEED = MD[1000]
# Unlike SHA-3's MCT, the output length itself changes every one of the
# 1000 inner rounds, driven by the digest that round just produced.
@parameter
def check_shake_mct[T: XofEngine](vectors: List[ShakeMctTestVector]) raises:
    for v in vectors:
        var msg = "[{}], count={}".format(reflect[T].name(), v.count)
        var out_range = v.max_bytes - v.min_bytes + 1

        var md = v.seed.copy()
        var out_len = v.max_bytes
        for j in range(len(v.checkpoints)):
            for _ in range(1000):
                var input = List[UInt8](capacity=16)
                var take = min(len(md), 16)
                for i in range(take):
                    input.append(md[i])
                for _ in range(16 - take):
                    input.append(0)

                var h = T()
                h.update(input[:])
                md = List[UInt8](length=out_len, fill=0)
                h.squeeze(Span(md))

                var rightmost = (Int(md[out_len - 2]) << 8) | Int(
                    md[out_len - 1]
                )
                out_len = v.min_bytes + (rightmost % out_range)

            assert_equal(
                md, v.checkpoints[j], msg="{}, checkpoint={}".format(msg, j)
            )


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/SHA3-224-2.0
# LDT (large-data test) vectors are intentionally not covered: the smallest
# message across the downloaded SHA3-*-2.0 sets is 1 GiB, which the naive
# backend (the only one SHA-3 has today) is far too slow to hash in a test
# run.
def test_sha3_224_aft() raises:
    var raw = load_python_acvp_vectors("tests/acvp/data/SHA3-224-2.0", "AFT")
    run_sha3_224_checks[check_sha3_aft](parse_acvp_sha3_aft(raw))


def test_sha3_224_mct() raises:
    var raw = load_python_acvp_vectors("tests/acvp/data/SHA3-224-2.0", "MCT")
    run_sha3_224_checks[check_sha3_mct](parse_acvp_sha3_mct(raw))


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/SHA3-256-2.0
def test_sha3_256_aft() raises:
    var raw = load_python_acvp_vectors("tests/acvp/data/SHA3-256-2.0", "AFT")
    run_sha3_256_checks[check_sha3_aft](parse_acvp_sha3_aft(raw))


def test_sha3_256_mct() raises:
    var raw = load_python_acvp_vectors("tests/acvp/data/SHA3-256-2.0", "MCT")
    run_sha3_256_checks[check_sha3_mct](parse_acvp_sha3_mct(raw))


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/SHA3-384-2.0
def test_sha3_384_aft() raises:
    var raw = load_python_acvp_vectors("tests/acvp/data/SHA3-384-2.0", "AFT")
    run_sha3_384_checks[check_sha3_aft](parse_acvp_sha3_aft(raw))


def test_sha3_384_mct() raises:
    var raw = load_python_acvp_vectors("tests/acvp/data/SHA3-384-2.0", "MCT")
    run_sha3_384_checks[check_sha3_mct](parse_acvp_sha3_mct(raw))


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/SHA3-512-2.0
def test_sha3_512_aft() raises:
    var raw = load_python_acvp_vectors("tests/acvp/data/SHA3-512-2.0", "AFT")
    run_sha3_512_checks[check_sha3_aft](parse_acvp_sha3_aft(raw))


def test_sha3_512_mct() raises:
    var raw = load_python_acvp_vectors("tests/acvp/data/SHA3-512-2.0", "MCT")
    run_sha3_512_checks[check_sha3_mct](parse_acvp_sha3_mct(raw))


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/SHAKE-128-1.0
def test_shake128_aft() raises:
    var raw = load_python_acvp_vectors("tests/acvp/data/SHAKE-128-1.0", "AFT")
    run_shake128_checks[check_shake_test](parse_acvp_shake_test(raw))


def test_shake128_vot() raises:
    var raw = load_python_acvp_vectors("tests/acvp/data/SHAKE-128-1.0", "VOT")
    run_shake128_checks[check_shake_test](parse_acvp_shake_test(raw))


def test_shake128_mct() raises:
    var raw = load_python_acvp_vectors("tests/acvp/data/SHAKE-128-1.0", "MCT")
    run_shake128_checks[check_shake_mct](parse_acvp_shake_mct(raw))


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/SHAKE-256-1.0
def test_shake256_aft() raises:
    var raw = load_python_acvp_vectors("tests/acvp/data/SHAKE-256-1.0", "AFT")
    run_shake256_checks[check_shake_test](parse_acvp_shake_test(raw))


def test_shake256_vot() raises:
    var raw = load_python_acvp_vectors("tests/acvp/data/SHAKE-256-1.0", "VOT")
    run_shake256_checks[check_shake_test](parse_acvp_shake_test(raw))


def test_shake256_mct() raises:
    var raw = load_python_acvp_vectors("tests/acvp/data/SHAKE-256-1.0", "MCT")
    run_shake256_checks[check_shake_mct](parse_acvp_shake_mct(raw))


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/SHAKE-128-FIPS202
# Byte-aligned-only revision: AFT is the only group type it defines.
def test_shake128_fips202_aft() raises:
    var raw = load_python_acvp_vectors(
        "tests/acvp/data/SHAKE-128-FIPS202", "AFT"
    )
    run_shake128_checks[check_shake_test](parse_acvp_shake_test(raw))


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/SHAKE-256-FIPS202
def test_shake256_fips202_aft() raises:
    var raw = load_python_acvp_vectors(
        "tests/acvp/data/SHAKE-256-FIPS202", "AFT"
    )
    run_shake256_checks[check_shake_test](parse_acvp_shake_test(raw))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
