use aes::cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BenchmarkGroup, BenchmarkId, Criterion,
};

const BLOCKS_256: usize = 256;
const BLOCKS_1K: usize = 1024;
const BLOCKS_4K: usize = 4096;

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
    for n in [BLOCKS_256, BLOCKS_1K, BLOCKS_4K] {
        group.bench_with_input(
            BenchmarkId::new("encrypt", format!("{}blk", n)),
            &n,
            |b, &n| {
                let mut blocks = vec![Block::<C>::default(); n];
                b.iter(|| cipher.encrypt_blocks(&mut blocks))
            },
        );
        group.bench_with_input(
            BenchmarkId::new("decrypt", format!("{}blk", n)),
            &n,
            |b, &n| {
                let mut blocks = vec![Block::<C>::default(); n];
                b.iter(|| cipher.decrypt_blocks(&mut blocks))
            },
        );
    }
}

criterion_group!(benches, bench_aes128, bench_aes192, bench_aes256);
criterion_main!(benches);
