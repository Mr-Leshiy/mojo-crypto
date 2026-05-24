use aes::cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BenchmarkGroup, BenchmarkId, Criterion,
};

const BLOCKS_256: usize = 256;
const BLOCKS_1K: usize = 1_024;
const BLOCKS_4K: usize = 4_096;
const BLOCKS_8K: usize = 8_192;
const BLOCKS_16K: usize = 16_384;

fn bench_aes128(c: &mut Criterion) {
    let cipher = Aes128::new_from_slice(&[0u8; 16]).unwrap();
    let mut group = c.benchmark_group("aes128_cpu");
    bench_all_block_counts(&mut group, &cipher);
    group.finish();
}

fn bench_aes192(c: &mut Criterion) {
    let cipher = Aes192::new_from_slice(&[0u8; 24]).unwrap();
    let mut group = c.benchmark_group("aes192_cpu");
    bench_all_block_counts(&mut group, &cipher);
    group.finish();
}

fn bench_aes256(c: &mut Criterion) {
    let cipher = Aes256::new_from_slice(&[0u8; 32]).unwrap();
    let mut group = c.benchmark_group("aes256_cpu");
    bench_all_block_counts(&mut group, &cipher);
    group.finish();
}

fn bench_all_block_counts<C: BlockCipherEncrypt + BlockCipherDecrypt>(
    group: &mut BenchmarkGroup<WallTime>,
    cipher: &C,
) {
    for (n, label) in [
        (BLOCKS_256, "256b"),
        (BLOCKS_1K, "1kb"),
        (BLOCKS_4K, "4kb"),
        (BLOCKS_8K, "8kb"),
        (BLOCKS_16K, "16kb"),
    ] {
        group.bench_function(BenchmarkId::new("encrypt", label), |b| {
            let mut blocks = vec![Block::<C>::default(); n / C::block_size()];
            b.iter(|| cipher.encrypt_blocks(&mut blocks))
        });
        group.bench_function(BenchmarkId::new("decrypt", label), |b| {
            let mut blocks = vec![Block::<C>::default(); n / C::block_size()];
            b.iter(|| cipher.decrypt_blocks(&mut blocks))
        });
    }
}

criterion_group!(benches, bench_aes128, bench_aes192, bench_aes256);
criterion_main!(benches);
