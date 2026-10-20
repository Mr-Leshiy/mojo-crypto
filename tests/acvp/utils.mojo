from std.python import Python, PythonObject


def load_python_acvp_vectors(
    vector_set: String, test_type: String
) raises -> PythonObject:
    """Requests `vector_set` (a registration in tests/acvp/registrations/) from
    the ACVP server and returns its `test_type` test cases."""
    var sys = Python.import_module("sys")
    sys.path.insert(0, PythonObject("tests/acvp"))
    var read_acvp_vectors = Python.import_module("read_acvp_vectors")
    return read_acvp_vectors.load(
        vector_set, read_acvp_vectors.TestType(test_type)
    )
