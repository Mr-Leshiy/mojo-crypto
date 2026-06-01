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


def read_avcp_aes[
    KeySize: Int, BlockSize: Int = 16
](dir: String, test_type: String) raises -> List[AesTestVector[KeySize, BlockSize]]:
    var sys = Python.import_module("sys")
    sys.path.insert(0, PythonObject("tests/block_ciphers/aes"))
    var read_acvp_vectors = Python.import_module("read_acvp_vectors")
    var python_vectors = read_acvp_vectors.load(dir, read_acvp_vectors.TestType(test_type))

    var vectors = List[AesTestVector[KeySize, BlockSize]]()
    for v in python_vectors:
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
                file_name=dir,
            )
        )
    return vectors^
