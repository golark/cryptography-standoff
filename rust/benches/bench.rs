use criterion::{criterion_group, criterion_main, Criterion};
use rust_vs_c::aes128::Aes128;
use rust_vs_c::aes128_neon::aes128_encrypt_ecb_neon;
use rust_vs_c::sha256::{sha256, DIGEST_SIZE};
use rust_vs_c::sha256_neon::sha256_neon;

const AES_DEMO_KEY: [u8; 16] = *b"rust-vs-c aes128";

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

    c.bench_function("sha256_neon_43B", |b| {
        b.iter(|| {
            let mut d = [0u8; DIGEST_SIZE];
            sha256_neon(criterion::black_box(small), &mut d);
            d
        })
    });

    c.bench_function("sha256_neon_4KiB", |b| {
        b.iter(|| {
            let mut d = [0u8; DIGEST_SIZE];
            sha256_neon(criterion::black_box(&large), &mut d);
            d
        })
    });
}

fn bench_aes128(c: &mut Criterion) {
    let ctx = Aes128::new(&AES_DEMO_KEY);
    // 43-byte demo message zero-padded to the 16-byte boundary, as in the C harness
    let small = b"The quick brown fox jumps over the lazy dog\x00\x00\x00\x00\x00";
    let large = vec![0u8; 4096];

    c.bench_function("aes128_48B", |b| {
        b.iter(|| {
            let mut out = [0u8; 48];
            Aes128::encrypt_ecb(&ctx, criterion::black_box(small), &mut out);
            out
        })
    });

    c.bench_function("aes128_4KiB", |b| {
        b.iter(|| {
            let mut out = vec![0u8; 4096];
            Aes128::encrypt_ecb(&ctx, criterion::black_box(&large), &mut out);
            out
        })
    });

    c.bench_function("aes128_neon_48B", |b| {
        b.iter(|| {
            let mut out = [0u8; 48];
            aes128_encrypt_ecb_neon(&ctx, criterion::black_box(small), &mut out);
            out
        })
    });

    c.bench_function("aes128_neon_4KiB", |b| {
        b.iter(|| {
            let mut out = vec![0u8; 4096];
            aes128_encrypt_ecb_neon(&ctx, criterion::black_box(&large), &mut out);
            out
        })
    });
}

criterion_group!(benches, bench_sha256, bench_aes128);
criterion_main!(benches);
