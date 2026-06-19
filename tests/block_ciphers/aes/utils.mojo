from std.python import Python, PythonObject

from mojo_crypto.containers.encoding import Hex


@fieldwise_init
struct AesTestVector(Copyable, Movable):
    var is_encrypt: Bool
    var count: Int
    var key: List[UInt8]
    # Fixed 16-byte IV for the block-cipher modes (CBC/CTR); None otherwise.
    var iv: List[UInt8]
    var pt: List[UInt8]
    var ct: List[UInt8]
    var file_name: String
    # AEAD (GCM) fields; empty / default for the block-cipher modes.
    # GCM nonce is variable length (commonly 12 bytes), so not a fixed array.
    var aad: List[UInt8]
    # Authentication tag, possibly truncated (tagLen varies per group).
    var tag: List[UInt8]
    # For decrypt vectors: whether authentication is expected to succeed.
    var test_passed: Bool


def load_python_acvp_vectors(
    dir: String, test_type: String
) raises -> PythonObject:
    var sys = Python.import_module("sys")
    sys.path.insert(0, PythonObject("tests/block_ciphers/aes"))
    var read_acvp_vectors = Python.import_module("read_acvp_vectors")
    return read_acvp_vectors.load(dir, read_acvp_vectors.TestType(test_type))


def parse_acvp_aes(
    python_vectors: PythonObject,
) raises -> List[AesTestVector]:
    var vectors = List[AesTestVector]()
    hex = Hex()
    for v in python_vectors:
        var iv = List[UInt8]()
        if v.iv_hex is not Python.none():
            iv = hex.decode(String(v.iv_hex))
        var aad = List[UInt8]()
        if v.aad_hex is not Python.none():
            aad = hex.decode(String(v.aad_hex))
        var tag = List[UInt8]()
        if v.tag_hex is not Python.none():
            tag = hex.decode(String(v.tag_hex))
        vectors.append(
            AesTestVector(
                is_encrypt=v.is_encrypt.__bool__(),
                count=atol(String(v.count)),
                key=hex.decode(String(v.key_hex)),
                iv=iv^,
                pt=hex.decode(String(v.pt_hex)),
                ct=hex.decode(String(v.ct_hex)),
                file_name=String(""),
                aad=aad^,
                tag=tag^,
                test_passed=v.test_passed.__bool__(),
            )
        )
    return vectors^
