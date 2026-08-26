use std::env;
use std::hint::black_box;
use std::time::Instant;

use rust_vs_c::aes128::Aes128;
use rust_vs_c::aes128_neon::aes128_encrypt_ecb_neon;
use rust_vs_c::sha256::{hex_digest, sha256, DIGEST_SIZE};
use rust_vs_c::sha256_neon::sha256_neon;

type Aes128EcbFn = fn(&Aes128, &[u8], &mut [u8]);

// Demo key for the AES track ("rust-vs-c aes128", 16 bytes).
const AES_DEMO_KEY: [u8; 16] = *b"rust-vs-c aes128";

const AES_BLOCK: usize = 16;

type Sha256Fn = fn(&[u8], &mut [u8; DIGEST_SIZE]);

struct Timer(Instant);

impl Timer {
    fn start() -> Timer {
        Timer(Instant::now())
    }
    fn elapsed_secs(&self) -> f64 {
        self.0.elapsed().as_secs_f64()
    }
}

fn run_bench(fn_: Sha256Fn, name: &str, input: &[u8], iters: u64) {
    let mut digest = [0u8; DIGEST_SIZE];
    let mut sink = 0u8;

    // warmup
    for _ in 0..1000 {
        fn_(black_box(input), &mut digest);
        sink ^= digest[0];
    }

    let t = Timer::start();
    for _ in 0..iters {
        fn_(black_box(input), &mut digest);
        sink ^= digest[0];
    }
    let elapsed = t.elapsed_secs();

    let avg_ns = elapsed * 1e9 / iters as f64;
    let mbps = (input.len() as f64 * iters as f64 / elapsed) / (1024.0 * 1024.0);

    println!("bench [{}]: {} bytes x {} iters", name, input.len(), iters);
    println!("total:      {:.3} ms", elapsed * 1e3);
    println!("avg:        {:.0} ns/hash", avg_ns);
    println!("throughput: {:.2} MB/s", mbps);
    println!("(sink {:02x})", sink);
}

fn padded_len(len: usize) -> usize {
    let plen = len.div_ceil(AES_BLOCK) * AES_BLOCK;
    plen.max(AES_BLOCK)
}

fn run_bench_aes(ecb: Aes128EcbFn, name: &str, input: &[u8], iters: u64) {
    let ctx = Aes128::new(&AES_DEMO_KEY);
    let plen = padded_len(input.len());
    let nblocks = plen / AES_BLOCK;

    let mut buf = vec![0u8; plen];
    buf[..input.len()].copy_from_slice(input);
    let mut out = vec![0u8; plen];
    let mut sink = 0u8;

    // warmup
    for _ in 0..1000 {
        ecb(&ctx, black_box(&buf), &mut out);
        sink ^= out[0];
    }

    let t = Timer::start();
    for _ in 0..iters {
        ecb(&ctx, black_box(&buf), &mut out);
        sink ^= out[0];
    }
    let elapsed = t.elapsed_secs();

    let avg_ns_block = elapsed * 1e9 / (iters as f64 * nblocks as f64);
    let mbps = (plen as f64 * iters as f64 / elapsed) / (1024.0 * 1024.0);

    println!(
        "bench [aes128 {}]: {} bytes ({} blocks) x {} iters",
        name, plen, nblocks, iters
    );
    println!("total:      {:.3} ms", elapsed * 1e3);
    println!("avg:        {:.1} ns/block", avg_ns_block);
    println!("throughput: {:.2} MB/s", mbps);
    println!("(sink {:02x})", sink);
}

fn print_hex(buf: &[u8]) {
    for b in buf {
        print!("{:02x}", b);
    }
    println!();
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut f: Sha256Fn = sha256;
    let mut impl_name = "scalar";
    let mut bench = false;
    let mut aes = false;
    let mut positional: Vec<&String> = Vec::new();

    for arg in &args[1..] {
        match arg.as_str() {
            "--neon" => {
                f = sha256_neon;
                impl_name = "neon";
            }
            "--scalar" => {
                f = sha256;
                impl_name = "scalar";
            }
            "--aes" => aes = true,
            "--sha256" => aes = false,
            "--bench" => bench = true,
            _ => positional.push(arg),
        }
    }

    if positional.len() > 2 || (!bench && positional.is_empty()) {
        println!("Usage: rust_vs_c [--sha256|--aes] [--neon|--scalar] <input string>");
        println!("       rust_vs_c --bench [--sha256|--aes] [--neon|--scalar] [input string] [iterations]");
        std::process::exit(1);
    }

    let aes_ecb: Aes128EcbFn = if impl_name == "neon" {
        aes128_encrypt_ecb_neon
    } else {
        Aes128::encrypt_ecb
    };

    let msg = positional
        .first()
        .map(|s| s.as_str())
        .unwrap_or("The quick brown fox jumps over the lazy dog");
    let iters: u64 = positional
        .get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(100_000);
    let input = msg.as_bytes();

    if bench {
        if aes {
            run_bench_aes(aes_ecb, impl_name, input, iters);
        } else {
            run_bench(f, impl_name, input, iters);
        }
        return;
    }

    if aes {
        let ctx = Aes128::new(&AES_DEMO_KEY);
        let plen = padded_len(input.len());
        let mut buf = vec![0u8; plen];
        buf[..input.len()].copy_from_slice(input);
        let mut out = vec![0u8; plen];
        aes_ecb(&ctx, &buf, &mut out);
        print_hex(&out);
        return;
    }

    let mut digest = [0u8; DIGEST_SIZE];
    f(input, &mut digest);
    println!("{}", hex_digest(&digest));
}
