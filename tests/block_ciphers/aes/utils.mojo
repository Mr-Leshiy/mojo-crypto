from std.python import Python, PythonObject
from std.memory import memcpy

from mojo_crypto.block_ciphers.aes import BLOCK_SIZE
from mojo_crypto.containers.encoding import Hex


@fieldwise_init
struct AesTestVector[KeySize: Int](Copyable, Movable):
    var is_encrypt: Bool
    var count: Int
    var key: InlineArray[UInt8, Self.KeySize]
    var iv: Optional[InlineArray[UInt8, BLOCK_SIZE]]
    var pt: List[UInt8]
    var ct: List[UInt8]
    var file_name: String


def parse_hex[N: Int](s: String) raises -> InlineArray[UInt8, N]:
    var result = InlineArray[UInt8, N](uninitialized=True)

    var bytes = Hex().decode(s)
    if len(bytes) != N:
        raise Error("Provided '{}' must have {} size".format(s, N))
    memcpy(dest=result.unsafe_ptr(), src=bytes.unsafe_ptr(), count=N)
    return result^


def load_python_acvp_vectors(
    dir: String, test_type: String
) raises -> PythonObject:
    var sys = Python.import_module("sys")
    sys.path.insert(0, PythonObject("tests/block_ciphers/aes"))
    var read_acvp_vectors = Python.import_module("read_acvp_vectors")
    return read_acvp_vectors.load(dir, read_acvp_vectors.TestType(test_type))


def parse_acvp_aes[
    KeySize: Int
](python_vectors: PythonObject) raises -> List[AesTestVector[KeySize]]:
    var vectors = List[AesTestVector[KeySize]]()
    for v in python_vectors:
        if atol(String(v.key_len)) // 8 != KeySize:
            continue
        var iv = Optional[InlineArray[UInt8, BLOCK_SIZE]](None)
        if v.iv_hex is not Python.none():
            iv = parse_hex[BLOCK_SIZE](String(v.iv_hex))
        vectors.append(
            AesTestVector(
                is_encrypt=v.is_encrypt.__bool__(),
                count=atol(String(v.count)),
                key=parse_hex[KeySize](String(v.key_hex)),
                iv=iv,
                pt=Hex().decode(String(v.pt_hex)),
                ct=Hex().decode(String(v.ct_hex)),
                file_name=String(""),
            )
        )
    return vectors^
