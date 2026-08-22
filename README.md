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
| **SHA-256** | Scalar | *— MB/s* | *— MB/s* | *—* |
| **SHA-256** | ARMv8 Crypto | *— MB/s* | *— MB/s* | *—* |
| **AES-128** | Scalar | *— MB/s* | *— MB/s* | *—* |
| **AES-128** | Hardware | *— MB/s* | *— MB/s* | *—* |
| **Ed25519** | Scalar | *— ops/sec* | *— ops/sec* | *—* |
| **Ed25519** | NEON SIMD | *— ops/sec* | *— ops/sec* | *—* |
