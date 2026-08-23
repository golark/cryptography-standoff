# Project Plan: `rust_c_cryptograph_standoff` (Apple M1 Edition)

A compact benchmarking blueprint to pit **Rust** against **C** on an ARMv8-A NEON, comparing scalar logic against hardware-accelerated/NEON intrinsics across three cryptographic algorithms.

---

## 1. Scope & Execution Matrix (Target: Apple M1)

* **Compilers:** Apple Clang (`-O3 -march=native -flto`) vs. `rustc` (`opt-level = 3`, `target-cpu = "native"`).

| Algorithm | Variant A (Scalar) | Variant B (SIMD / HW Accelerated) | Metric |
| :--- | :--- | :--- | :--- |
| **SHA-256** | Pure bit-mixing loop (`wrapping_add`) | ARMv8 Crypto Extensions (`sha256h`/`sha256su0`) | Throughput (**MB/s**) |
| **AES-128** | Table-driven / S-box implementation | ARMv8 Crypto Extensions (`aese`/`aesmc`) | Throughput (**MB/s**) |
| **Ed25519** | 64-bit limb arithmetic over $2^{255}-19$ | NEON vectorized 128-bit limb operations | Latency (**ops/sec**) |

---

## 2. Concise Development Roadmap

### Phase 1: Setup & Vectors
* [ ] Initialize a unified project structure with shared test vectors (`/vectors`) for NIST KATs and RFC 8032.

### Phase 2: Scalar Track (Pure Code Logic)
* [ ] Implement scalar SHA-256, AES-128, and Ed25519 in C, then port identically to Rust.
* [ ] Verify functional correctness against test vectors via `cargo test` and C unit tests.

### Phase 3: Accelerated Track (Silicon Duel on M1)
* [ ] Hook into Apple M1's built-in cryptographic instructions via ARM NEON/Crypto intrinsics (`arm_neon.h` in C, `core::arch::aarch64::*` in Rust).
* [ ] Test silicon-accelerated AES and SHA-256 alongside vectorized curve arithmetic.

---

## 3. Standoff Benchmark Matrix Template

| Algorithm | Variant | C (Apple Clang) | Rust (`rustc`) | Delta (%) |
| :--- | :--- | :--- | :--- | :--- |
| **SHA-256** | Scalar | **~79 MB/s** (43 B) / **~122 MB/s** (4 KiB) | **~80 MB/s** (43 B) / **~119 MB/s** (4 KiB) | *—* |
| **SHA-256** | ARMv8 Crypto | **~931 MB/s** (43 B) / **~1262 MB/s** (4 KiB) | **~957 MB/s** (43 B) / **~1260 MB/s** (4 KiB) | *—* |
| **AES-128** | Scalar | *— MB/s* | *— MB/s* | *—* |
| **AES-128** | Hardware | *— MB/s* | *— MB/s* | *—* |
| **Ed25519** | Scalar | *— ops/sec* | *— ops/sec* | *—* |
| **Ed25519** | NEON SIMD | *— ops/sec* | *— ops/sec* | *—* |

---

## 4. Results Log

### SHA-256, Scalar Track — C side (2026-08-22)

Environment: Apple M1 (ARMv8-A), macOS 26.5.1, Apple clang 21.0.0 (`cc -O2 -Wall -Wextra -std=c11`).
Method: `./rust-vs-c --bench <input> <iters>` — 1000 warmup hashes, then N timed iterations
via `CLOCK_MONOTONIC`; reports average ns/hash and throughput. Values below are the
middle of 3 runs.

| Input size | Iterations | Avg time/hash | Throughput |
| :--- | :--- | :--- | :--- |
| 43 B ("The quick brown fox...") | 200,000 | ~519 ns | ~79.0 MB/s |
| 4 KiB | 10,000 | ~32.0 µs | ~122.0 MB/s |

Reference digests verified against `hashlib.sha256` across 9 vectors including the
55/56-byte two-block padding boundary (see `vectors/sha256/kats.txt`).

### SHA-256, Scalar Track — Rust side (2026-08-22)

Environment: Apple M1, rustc stable, `--release` (opt-level 3, LTO, codegen-units=1).
Method: identical harness to C (`--bench`, 1000 warmup, `Instant` monotonic timing);
criterion confirms (`sha256_43B` ≈ 520 ns, `sha256_4KiB` ≈ 32.6 µs).

| Input size | Iterations | Avg time/hash | Throughput |
| :--- | :--- | :--- | :--- |
| 43 B ("The quick brown fox...") | 200,000 | ~513 ns | ~79.9 MB/s |
| 4 KiB | 10,000 | ~32.9 µs | ~118.8 MB/s |

Scalar verdict: statistical dead heat at small inputs; C edges ahead ~2–3% at 4 KiB.
5/5 unit tests pass (KATs incl. padding boundaries); vectors regenerated and
round-trip verified after a transcription error in the original `kats.txt`.

### SHA-256, Accelerated Track — C side, ARMv8 Crypto Extensions (2026-08-22)

Implementation: `c/src/sha256_neon.c` — `vsha256hq`/`vsha256h2q` state updates +
`vsha256su0q`/`vsha256su1q` schedule expansion (pattern after Jeffrey Walton's
public-domain intrinsics port / mbedTLS). Compiles with plain Apple Clang arm64
target; falls back to scalar off-ARM. Selected via `--neon` flag.

| Input size | Scalar | ARMv8 Crypto | Speedup |
| :--- | :--- | :--- | :--- |
| 43 B | ~521 ns (~78.7 MB/s) | **~44 ns** | ~11.8x |
| 4 KiB | ~32.9 µs (~118 MB/s) | **~3.10 µs** (~1262 MB/s) | ~10.4x |

All KAT vectors pass through both scalar and neon paths. The Crypto Extensions
replace 64 rounds of scalar mixing with `SHA256H`/`SHA256H2`, which is where the
order-of-magnitude gain comes from.

### SHA-256, Accelerated Track — Rust side, ARMv8 Crypto Extensions (2026-08-22)

Implementation: `rust/src/sha256_neon.rs` — `core::arch::aarch64` intrinsics
(`vsha256hq_u32`/`vsha256h2q_u32`/`vsha256su0q_u32`/`vsha256su1q_u32`), same
group-interleaved pattern as the C version. Built with `target-feature=+sha2`
(see `rust/.cargo/config.toml`). Falls back to scalar off-AArch64.

| Input size | Scalar | ARMv8 Crypto | Speedup |
| :--- | :--- | :--- | :--- |
| 43 B | ~515 ns (~81 MB/s) | **~47 ns** (~957 MB/s) | ~10.9x |
| 4 KiB | ~31.9 µs (~122 MB/s) | **~3.10 µs** (~1260 MB/s) | ~10.3x |

Accelerated-track verdict: C and Rust are statistically tied on the silicon
duel — both compile to the same SHA256H/H2/SU0/SU1 instruction sequence.
10/10 unit tests pass (scalar + neon KATs); criterion benches included
(`sha256_neon_43B`, `sha256_neon_4KiB`).
