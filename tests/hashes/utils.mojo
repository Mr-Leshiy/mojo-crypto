from std.testing import assert_equal

from mojo_crypto.utils.hex import hex_decode
from mojo_crypto.hashes.traits import Digest


def check_hash[
    T: Digest & Movable & ImplicitlyDestructible
](msg: String, expected_hex: String) raises:
    var h = T()
    h.update(msg.as_bytes())
    assert_equal(h^.finalize(), hex_decode[T.OUTPUT_SIZE](expected_hex))
