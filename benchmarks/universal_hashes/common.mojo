from std.benchmark import run, keep

from mojo_crypto.universal_hashes.traits import UniversalHashable

comptime BYTES_1K: Int = 1_024
comptime BYTES_16K: Int = 16_384


def bench_uhash[
    H: UniversalHashable & ImplicitlyDestructible,
    prefix: StringLiteral,
]() raises:
    var key = InlineArray[UInt8, H.KEY_SIZE](fill=0)

    @parameter
    def bench[N: Int, suffix: StringLiteral]() raises:
        # Heap-allocate the input so it isn't a stack constant. `keep` then
        # forces the optimizer to treat the buffer as opaque and to observe the
        # tag — without this the all-zero input is constant-folded and the whole
        # hash is dead-code-eliminated, producing meaningless (~1e-17 s) timings.
        var data = List[UInt8](length=N, fill=0)

        @parameter
        def do_hash() raises:
            keep(data.unsafe_ptr())
            var hash = H(key)
            hash.update(Span(data))
            var tag = hash^.finalize()
            keep(tag.unsafe_ptr())

        run[do_hash]().print(prefix + "_" + suffix)

    bench[BYTES_1K, "1kb"]()
    bench[BYTES_16K, "16kb"]()
