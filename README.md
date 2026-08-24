A compact benchmarking blueprint to pit **Rust** against **C** on an ARMv8-A NEON. Scalar, vs Neon-Intrinsics for SHA-256, AES-128 and ED25519 - usual suspects



---

## Benchmark Matrix 

| Algorithm | Variant | Implementation | C | Rust |
| :--- | :--- | :--- | :--- | :--- |
| **SHA-256** | Scalar - bit-wise ops | [sha256.c](c/src/sha256.c) · [sha256.rs](rust/src/sha256.rs) | **~79 MB/s** (43 B) / **~122 MB/s** (4 KiB) | **~80 MB/s** (43 B) / **~119 MB/s** (4 KiB) |
| **SHA-256** | ARMv8 Crypto Intrinsics | [sha256_neon.c](c/src/sha256_neon.c) · [sha256_neon.rs](rust/src/sha256_neon.rs) | **~931 MB/s** (43 B) / **~1262 MB/s** (4 KiB) | **~957 MB/s** (43 B) / **~1260 MB/s** (4 KiB) |
| **AES-128** | Scalar | [aes128.c](c/src/aes128.c) · [aes128.rs](rust/src/aes128.rs) | **~225 MB/s** (48 B) / **~227 MB/s** (4 KiB) | **~253 MB/s** (48 B) / **~256 MB/s** (4 KiB) |
| **AES-128** | ARMv8 Crypto Extensions (aese/aesmc)| *—* | *— MB/s* | *— MB/s* |
| **Ed25519** | Scalar | *—* | *— ops/sec* | *— ops/sec* |
| **Ed25519** | NEON SIMD vectorized 128-bit limb operations | *—* | *— ops/sec* | *— ops/sec* |

---

## Results Log

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

### AES-128, Scalar Track — C side (2026-08-24)

Implementation: `c/src/aes128.c` — classic T-table scalar design
(rijndael-alg-fst style): 9 fused SubBytes/ShiftRows/MixColumns rounds via
`TE0`–`TE3` lookups, final round through replicated-S-box `TE4`, word-based key
schedule per FIPS-197. Tables generated programmatically (GF(2^8) inverse +
affine map), not transcribed. Endianness-independent via byte-wise GETU32/PUTU32.

Verification: built-in selftests (`rust-vs-c --selftest`, wired to `make test`)
cover FIPS-197 C.1, NIST SP 800-38A F.1.1 four-block ECB sequence, and zero/all-ff
edge vectors; KAT set mirrored in `vectors/aes128/kats.txt`. Additionally passed a
2000-vector randomized differential test against an independent pure-Python
reference. First cut had a real bug worth recording: assigning final-round results
back into the state words in place corrupted later columns (sequential dependence)
— caught immediately by the FIPS KAT, fixed with temporaries.

Bench method: identical harness to SHA-256 (`--bench --aes`, 1000 warmups,
`CLOCK_MONOTONIC`); demo key `"rust-vs-c aes128"`. Inputs are zero-padded to the
next 16-byte boundary and throughput is counted on the padded length, so "43 B"
is really 48 B. Values below are the middle of 3 runs.

| Input size | Iterations | Avg ns/block | Throughput |
| :--- | :--- | :--- | :--- |
| 43 B → 48 B | 200,000 | ~68 | ~225 MB/s |
| 4 KiB | 10,000 | ~67 | ~227 MB/s |

Throughput is flat across sizes (~15 cycles/byte on this part); the ARMv8 Crypto
Extensions track (`aese`/`aesmc`) is where the expected order-of-magnitude gap
will show up next.

### AES-128, Scalar Track — Rust side (2026-08-24)

Implementation: `rust/src/aes128.rs` — same T-table design as the C side
(struct-based API: `Aes128::new` key schedule, `encrypt_block`, `encrypt_ecb`
via `chunks_exact`). Tables extracted mechanically from `c/src/aes128.c` so both
languages run byte-identical constants. Built with `--release` (opt-level 3,
LTO, codegen-units=1).

Verification: 4 unit-test KATs (FIPS-197 C.1, SP 800-38A F.1.1 x4 ECB sequence,
zero and all-ff vectors) pass via `cargo test --release`; clippy clean. CLI
ciphertexts verified byte-identical to the C binary across 48 B / 4 KiB / odd-length
(777 B) inputs under the shared demo key.

Bench method: identical harness (`cargo run --release -- --bench --aes`,
1000 warmups, `Instant` monotonic timing); zero-padding to block boundary with
throughput counted on padded length, matching C. Middle of 3 runs:

| Input size | Iterations | Avg ns/block | Throughput |
| :--- | :--- | :--- | :--- |
| 43 B → 48 B | 200,000 | ~60 | ~253 MB/s |
| 4 KiB | 10,000 | ~59 | ~256 MB/s |

Rust verdict: ~12% ahead of C at the same algorithm (~60 vs ~68 ns/block) —
bounds-checked indexing elides to unchecked addressing here, and LTO/codegen-units=1
schedules the table-lookup chains slightly better. Criterion benches included
(`aes128_48B`, `aes128_4KiB`).
