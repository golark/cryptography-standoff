use std::env;
use std::hint::black_box;
use std::time::Instant;

use rust_vs_c::sha256::{hex_digest, sha256, DIGEST_SIZE};

fn now_ns() -> u128 {
    Instant::now().elapsed().as_nanos()
}

struct Timer(Instant);

impl Timer {
    fn start() -> Timer {
        Timer(Instant::now())
    }
    fn elapsed_secs(&self) -> f64 {
        self.0.elapsed().as_secs_f64()
    }
}

fn run_bench(input: &[u8], iters: u64) {
    let mut digest = [0u8; DIGEST_SIZE];
    let mut sink = 0u8;

    // warmup
    for _ in 0..1000 {
        sha256(black_box(input), &mut digest);
        sink ^= digest[0];
    }

    let t = Timer::start();
    for _ in 0..iters {
        sha256(black_box(input), &mut digest);
        sink ^= digest[0];
    }
    let elapsed = t.elapsed_secs();

    let avg_ns = elapsed * 1e9 / iters as f64;
    let mbps = (input.len() as f64 * iters as f64 / elapsed) / (1024.0 * 1024.0);

    println!("bench: {} bytes x {} iters", input.len(), iters);
    println!("total:      {:.3} ms", elapsed * 1e3);
    println!("avg:        {:.0} ns/hash", avg_ns);
    println!("throughput: {:.2} MB/s", mbps);
    println!("(sink {:02x})", sink & 0xff);
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() >= 2 && args[1] == "--bench" {
        let msg = args
            .get(2)
            .map(|s| s.as_str())
            .unwrap_or("The quick brown fox jumps over the lazy dog");
        let iters: u64 = args
            .get(3)
            .and_then(|s| s.parse().ok())
            .unwrap_or(100_000);
        run_bench(msg.as_bytes(), iters);
        return;
    }

    if args.len() < 2 {
        println!("Usage: rust_vs_c <input string>");
        println!("       rust_vs_c --bench [input string] [iterations]");
        std::process::exit(1);
    }

    let mut digest = [0u8; DIGEST_SIZE];
    sha256(args[1].as_bytes(), &mut digest);
    println!("{}", hex_digest(&digest));
}
