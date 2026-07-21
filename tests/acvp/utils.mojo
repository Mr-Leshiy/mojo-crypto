from std.python import Python, PythonObject


def load_python_acvp_vectors(
    dir: String, test_type: String
) raises -> PythonObject:
    var sys = Python.import_module("sys")
    sys.path.insert(0, PythonObject("tests/block_ciphers/aes"))
    var read_acvp_vectors = Python.import_module("read_acvp_vectors")
    return read_acvp_vectors.load(dir, read_acvp_vectors.TestType(test_type))
