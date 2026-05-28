from std.python import Python, PythonObject
from std.memory import memcpy

from mojo_crypto.containers.encoding import Hex


@fieldwise_init
struct AesTestVector[KeySize: Int, BlockSize: Int = 16](Copyable, Movable):
    var is_encrypt: Bool
    var count: Int
    var key: InlineArray[UInt8, Self.KeySize]
    var iv: Optional[InlineArray[UInt8, Self.BlockSize]]
    var pt: InlineArray[UInt8, Self.BlockSize]
    var ct: InlineArray[UInt8, Self.BlockSize]
    var file_name: String


def parse_hex[N: Int](s: String) raises -> InlineArray[UInt8, N]:
    var result = InlineArray[UInt8, N](uninitialized=True)

    var bytes = Hex().decode(s)
    if len(bytes) != N:
        raise Error("Provided '{}' must have {} size".format(s, N))
    memcpy(dest=result.unsafe_ptr(), src=bytes.unsafe_ptr(), count=N)
    return result^


def load_python_aes_vectors(dir: String, mode: String) raises -> PythonObject:
    var sys = Python.import_module("sys")
    sys.path.insert(0, PythonObject("tests/block_ciphers/aes"))
    var load_test_vectors = Python.import_module("load_test_vectors")
    return load_test_vectors.load(dir, load_test_vectors.Mode(mode))


def load_aes_vectors[
    KeySize: Int, BlockSize: Int = 16
](python_aes_vectors: PythonObject) raises -> List[
    AesTestVector[KeySize, BlockSize]
]:
    var vectors = List[AesTestVector[KeySize, BlockSize]]()
    for v in python_aes_vectors:
        var bits = atol(String(v.aes_type.value))
        if bits / 8 == KeySize:
            var iv = Optional[InlineArray[UInt8, BlockSize]](None)
            if v.iv_hex is not Python.none():
                iv = parse_hex[BlockSize](String(v.iv_hex))
            vectors.append(
                AesTestVector(
                    is_encrypt=v.is_encrypt.__bool__(),
                    count=atol(String(v.count)),
                    key=parse_hex[KeySize](String(v.key_hex)),
                    iv=iv,
                    pt=parse_hex[BlockSize](String(v.pt_hex)),
                    ct=parse_hex[BlockSize](String(v.ct_hex)),
                    file_name=String(v.file_name),
                )
            )
    return vectors^
