from std.python import Python, PythonObject


@fieldwise_init
struct AesTestVector[KeySize: Int](Copyable, Movable):
    var is_encrypt: Bool
    var key: InlineArray[UInt8, Self.KeySize]
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
    return result^


def load_python_aes_vectors(dir: String, mode: String) raises -> PythonObject:
    var sys = Python.import_module("sys")
    sys.path.insert(0, PythonObject("tests/block_ciphers/aes"))
    var load_test_vectors = Python.import_module("load_test_vectors")
    return load_test_vectors.load(dir, load_test_vectors.AesMode(mode))


def load_aes_vectors[
    KeySize: Int
](python_aes_vectors: PythonObject) raises -> List[AesTestVector[KeySize]]:
    var vectors = List[AesTestVector[KeySize]]()
    for v in python_aes_vectors:
        var bits = atol(String(v.aes_type.value))
        if bits / 8 == KeySize:
            var key = parse_hex[KeySize](String(v.key_hex))
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
