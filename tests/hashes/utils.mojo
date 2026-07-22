from std.testing import assert_equal

from mojo_crypto.containers.encoding import Hex
from mojo_crypto.hashes.traits import Digest


def check_hash[
    T: Digest & Movable & ImplicitlyDestructible
](msg: String, expected_hex: String) raises:
    var hex = Hex()
    var h = T()
    h.update(msg.as_bytes())
    assert_equal(h^.finalize(), hex.decode[T.OUTPUT_SIZE](expected_hex))
