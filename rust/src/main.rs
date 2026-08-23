use std::env;
use std::hint::black_box;
use std::time::Instant;

use rust_vs_c::sha256::{hex_digest, sha256, DIGEST_SIZE};
use rust_vs_c::sha256_neon::sha256_neon;

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
    println!("(sink {:02x})", sink & 0xff);
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut f: Sha256Fn = sha256;
    let mut impl_name = "scalar";
    let mut bench = false;
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
            "--bench" => bench = true,
            _ => positional.push(arg),
        }
    }

    if positional.len() > 2 || (!bench && positional.is_empty()) {
        println!("Usage: rust_vs_c [--neon|--scalar] <input string>");
        println!("       rust_vs_c --bench [--neon|--scalar] [input string] [iterations]");
        std::process::exit(1);
    }

    if bench {
        let msg = positional
            .first()
            .map(|s| s.as_str())
            .unwrap_or("The quick brown fox jumps over the lazy dog");
        let iters: u64 = positional
            .get(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(100_000);
        run_bench(f, impl_name, msg.as_bytes(), iters);
        return;
    }

    let mut digest = [0u8; DIGEST_SIZE];
    f(positional[0].as_bytes(), &mut digest);
    println!("{}", hex_digest(&digest));
}
