use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BenchmarkGroup, BenchmarkId, Criterion,
};
use ghash::GHash;
use polyval::universal_hash::{Key, KeyInit, UniversalHash};
use polyval::Polyval;

const BYTES_1K: usize = 1_024;
const BYTES_16K: usize = 16_384;

fn bench_polyval(c: &mut Criterion) {
    let mut group = c.benchmark_group("polyval");
    bench_all_sizes::<Polyval>(&mut group);
    group.finish();
}

fn bench_ghash(c: &mut Criterion) {
    let mut group = c.benchmark_group("ghash");
    bench_all_sizes::<GHash>(&mut group);
    group.finish();
}

fn bench_all_sizes<H: UniversalHash + KeyInit>(group: &mut BenchmarkGroup<WallTime>) {
    let key = Key::<H>::default();
    for (n, label) in [(BYTES_1K, "1kb"), (BYTES_16K, "16kb")] {
        let data = vec![0u8; n];
        // Mirror the Mojo scenario: construct from a zero key, absorb the whole
        // buffer, then finalize — all per iteration.
        group.bench_function(BenchmarkId::new("hash", label), |b| {
            b.iter(|| {
                let mut hash = H::new(&key);
                hash.update_padded(&data);
                hash.finalize()
            })
        });
    }
}

criterion_group!(benches, bench_polyval, bench_ghash);
criterion_main!(benches);
