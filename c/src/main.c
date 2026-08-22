#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sha256.h"

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static void print_digest(const uint8_t digest[SHA256_DIGEST_SIZE]) {
    for (int i = 0; i < SHA256_DIGEST_SIZE; ++i) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}

static int run_bench(const uint8_t *input, size_t len, long iters) {
    uint8_t digest[SHA256_DIGEST_SIZE];
    volatile uint8_t sink = 0;

    // warmup
    for (int i = 0; i < 1000; ++i) {
        sha256(input, len, digest);
        sink ^= digest[0];
    }

    double t0 = now_sec();
    for (long i = 0; i < iters; ++i) {
        sha256(input, len, digest);
        sink ^= digest[0];
    }
    double elapsed = now_sec() - t0;

    double avg_ns = (elapsed * 1e9) / (double)iters;
    double mbps = ((double)len * (double)iters / elapsed) / (1024.0 * 1024.0);

    printf("bench: %ld bytes x %ld iters\n", len, iters);
    printf("total:      %.3f ms\n", elapsed * 1e3);
    printf("avg:        %.0f ns/hash\n", avg_ns);
    printf("throughput: %.2f MB/s\n", mbps);
    printf("(sink %02x)\n", (unsigned)(sink & 0xff));

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc >= 2 && strcmp(argv[1], "--bench") == 0) {
        const char *msg = (argc >= 3) ? argv[2] : "The quick brown fox jumps over the lazy dog";
        long iters = (argc >= 4) ? atol(argv[3]) : 100000;
        return run_bench((const uint8_t *)msg, strlen(msg), iters);
    }

    if (argc < 2) {
        printf("Usage: rust-vs-c <input string>\n");
        printf("       rust-vs-c --bench [input string] [iterations]\n");
        return 1;
    }

    const uint8_t *input = (const uint8_t *)argv[1];
    size_t len = strlen(argv[1]);

    uint8_t digest[SHA256_DIGEST_SIZE];
    sha256(input, len, digest);
    print_digest(digest);

    return 0;
}
