use criterion::{criterion_group, criterion_main, Criterion};
use rust_vs_c::sha256::{sha256, DIGEST_SIZE};

fn bench_sha256(c: &mut Criterion) {
    let small = b"The quick brown fox jumps over the lazy dog";
    let large = vec![b'x'; 4096];

    c.bench_function("sha256_43B", |b| {
        b.iter(|| {
            let mut d = [0u8; DIGEST_SIZE];
            sha256(criterion::black_box(small), &mut d);
            d
        })
    });

    c.bench_function("sha256_4KiB", |b| {
        b.iter(|| {
            let mut d = [0u8; DIGEST_SIZE];
            sha256(criterion::black_box(&large), &mut d);
            d
        })
    });
}

criterion_group!(benches, bench_sha256);
criterion_main!(benches);
