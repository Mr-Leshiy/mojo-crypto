from std.utils import Variant
from std.python import Python, PythonObject


comptime AesKey = Variant[
    InlineArray[UInt8, 16], InlineArray[UInt8, 24], InlineArray[UInt8, 32]
]


@fieldwise_init
struct AesTestVector(Copyable, Movable):
    var is_encrypt: Bool
    var key: AesKey
    var pt: InlineArray[UInt8, 16]
    var ct: InlineArray[UInt8, 16]
    var file_name: String


@always_inline
def _hex_nibble(b: UInt8) -> UInt8:
    if b <= 57:
        return b - 48
    if b >= 97:
        return b - 87
    return b - 55


def parse_hex[N: Int](s: String) -> InlineArray[UInt8, N]:
    var result = InlineArray[UInt8, N](uninitialized=True)
    var ptr = s.unsafe_ptr()
    for i in range(N):
        result[i] = (_hex_nibble(ptr[2 * i]) << 4) | _hex_nibble(ptr[2 * i + 1])
    return result


def load_aes_vectors(dir: String, mode: String) raises -> List[AesTestVector]:
    var sys = Python.import_module("sys")
    sys.path.insert(0, PythonObject("mojo_crypto/aes"))
    var load_test_vectors = Python.import_module("load_test_vectors")
    var vectors = List[AesTestVector]()
    for v in load_test_vectors.load(dir, load_test_vectors.AesMode(mode)):
        var bits = atol(String(v.aes_type.value))
        var key: AesKey
        if bits == 128:
            key = parse_hex[16](String(v.key_hex))
        elif bits == 192:
            key = parse_hex[24](String(v.key_hex))
        else:
            key = parse_hex[32](String(v.key_hex))
        vectors.append(
            AesTestVector(
                is_encrypt=v.is_encrypt.__bool__(),
                key=key,
                pt=parse_hex[16](String(v.pt_hex)),
                ct=parse_hex[16](String(v.ct_hex)),
                file_name=String(v.file_name),
            )
        )
    return vectors^
