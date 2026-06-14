from sys import abort
from std.testing import assert_equal, TestSuite


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
