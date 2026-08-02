use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BenchmarkGroup, BenchmarkId, Criterion,
};
use sha2::{
    Digest, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256,
};

const BYTES_1K: usize = 1_024;
const BYTES_16K: usize = 16_384;

fn bench_sha2(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha2");
    bench_all_sizes::<Sha224>(&mut group, "sha224");
    bench_all_sizes::<Sha256>(&mut group, "sha256");
    bench_all_sizes::<Sha384>(&mut group, "sha384");
    bench_all_sizes::<Sha512>(&mut group, "sha512");
    bench_all_sizes::<Sha512_224>(&mut group, "sha512_224");
    bench_all_sizes::<Sha512_256>(&mut group, "sha512_256");
    group.finish();
}

fn bench_all_sizes<H: Digest>(group: &mut BenchmarkGroup<WallTime>, name: &str) {
    for (n, label) in [(BYTES_1K, "1kb"), (BYTES_16K, "16kb")] {
        let data = vec![0u8; n];
        // Mirror the Mojo scenario: construct a fresh hash, absorb the whole
        // buffer, then finalize — all per iteration.
        group.bench_function(BenchmarkId::new(name, label), |b| {
            b.iter(|| {
                let mut hash = H::new();
                hash.update(&data);
                hash.finalize()
            })
        });
    }
}

criterion_group!(benches, bench_sha2);
criterion_main!(benches);
