#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sha256.h"

typedef void (*sha256_fn)(const uint8_t *, size_t, uint8_t *);

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

static int run_bench(sha256_fn fn, const char *name, const uint8_t *input, size_t len,
                     long iters) {
    uint8_t digest[SHA256_DIGEST_SIZE];
    volatile uint8_t sink = 0;

    for (int i = 0; i < 1000; ++i) {
        fn(input, len, digest);
        sink ^= digest[0];
    }

    double t0 = now_sec();
    for (long i = 0; i < iters; ++i) {
        fn(input, len, digest);
        sink ^= digest[0];
    }
    double elapsed = now_sec() - t0;

    double avg_ns = (elapsed * 1e9) / (double)iters;
    double mbps = ((double)len * (double)iters / elapsed) / (1024.0 * 1024.0);

    printf("bench [%s]: %ld bytes x %ld iters\n", name, len, iters);
    printf("total:      %.3f ms\n", elapsed * 1e3);
    printf("avg:        %.0f ns/hash\n", avg_ns);
    printf("throughput: %.2f MB/s\n", mbps);
    printf("(sink %02x)\n", (unsigned)(sink & 0xff));

    return 0;
}

int main(int argc, char *argv[]) {
    sha256_fn fn = sha256;
    const char *impl_name = "scalar";
    int bench = 0;
    const char *positional[2] = {NULL, NULL};
    int npos = 0;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--neon") == 0) {
            fn = sha256_neon;
            impl_name = "neon";
        } else if (strcmp(argv[i], "--scalar") == 0) {
            fn = sha256;
            impl_name = "scalar";
        } else if (strcmp(argv[i], "--bench") == 0) {
            bench = 1;
        } else if (npos < 2) {
            positional[npos++] = argv[i];
        } else {
            npos = 3;
            break;
        }
    }

    if (npos > 2 || (!bench && npos < 1)) {
        printf("Usage: rust-vs-c [--neon|--scalar] <input string>\n");
        printf("       rust-vs-c --bench [--neon|--scalar] [input string] [iterations]\n");
        return 1;
    }

    if (bench) {
        const char *msg =
            positional[0] ? positional[0] : "The quick brown fox jumps over the lazy dog";
        long iters = positional[1] ? atol(positional[1]) : 100000;
        return run_bench(fn, impl_name, (const uint8_t *)msg, strlen(msg), iters);
    }

    uint8_t digest[SHA256_DIGEST_SIZE];
    fn((const uint8_t *)positional[0], strlen(positional[0]), digest);
    print_digest(digest);

    return 0;
}
