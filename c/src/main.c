#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "aes128.h"
#include "sha256.h"

// Demo key for the AES track ("rust-vs-c aes128", 16 bytes).
static const uint8_t AES_DEMO_KEY[AES128_KEY_SIZE] = {
    'r', 'u', 's', 't', '-', 'v', 's', '-', 'c', ' ', 'a', 'e', 's', '1', '2', '8',
};

typedef void (*sha256_fn)(const uint8_t *, size_t, uint8_t *);

enum { MODE_SHA256, MODE_AES };

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static void print_hex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static size_t unhex(const char *s, uint8_t *out) {
    size_t n = 0;
    while (s[n * 2] != '\0' && s[n * 2 + 1] != '\0') {
        int hi = hexval(s[n * 2]);
        int lo = hexval(s[n * 2 + 1]);
        if (hi < 0 || lo < 0) {
            break;
        }
        out[n] = (uint8_t)((hi << 4) | lo);
        ++n;
    }
    return n;
}

static int run_bench_sha(sha256_fn fn, const char *name, const uint8_t *input, size_t len,
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

static int run_bench_aes(const uint8_t *input, size_t len, long iters) {
    aes128_ctx ctx;
    aes128_key_expand(&ctx, AES_DEMO_KEY);

    size_t plen = ((len + AES128_BLOCK_SIZE - 1) / AES128_BLOCK_SIZE) * AES128_BLOCK_SIZE;
    if (plen == 0) {
        plen = AES128_BLOCK_SIZE;
    }
    size_t nblocks = plen / AES128_BLOCK_SIZE;

    uint8_t *buf = malloc(plen);
    uint8_t *out = malloc(plen);
    if (!buf || !out) {
        fprintf(stderr, "out of memory\n");
        free(buf);
        free(out);
        return 1;
    }
    memset(buf, 0, plen);
    memcpy(buf, input, len);

    volatile uint8_t sink = 0;
    for (int i = 0; i < 1000; ++i) {
        aes128_encrypt_ecb(&ctx, buf, plen, out);
        sink ^= out[0];
    }

    double t0 = now_sec();
    for (long i = 0; i < iters; ++i) {
        aes128_encrypt_ecb(&ctx, buf, plen, out);
        sink ^= out[0];
    }
    double elapsed = now_sec() - t0;

    double avg_ns_block = (elapsed * 1e9) / ((double)iters * (double)nblocks);
    double mbps = ((double)plen * (double)iters / elapsed) / (1024.0 * 1024.0);

    printf("bench [aes128 scalar]: %zu bytes (%zu blocks) x %ld iters\n", plen, nblocks, iters);
    printf("total:      %.3f ms\n", elapsed * 1e3);
    printf("avg:        %.1f ns/block\n", avg_ns_block);
    printf("throughput: %.2f MB/s\n", mbps);
    printf("(sink %02x)\n", (unsigned)(sink & 0xff));

    free(buf);
    free(out);
    return 0;
}

static int run_selftest(void) {
    static const struct {
        const char *msg;
        const char *digest;
    } SHA_KATS[] = {
        {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {"The quick brown fox jumps over the lazy dog",
         "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"},
    };
    static const struct {
        const char *key;
        const char *pt;
        const char *ct;
    } AES_KATS[] = {
        {"000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff",
         "69c4e0d86a7b0430d8cdb78070b4c55a"}, // FIPS-197 C.1
        {"00000000000000000000000000000000", "00000000000000000000000000000000",
         "66e94bd4ef8a2c3b884cfa59ca342b2e"},
        {"ffffffffffffffffffffffffffffffff", "ffffffffffffffffffffffffffffffff",
         "bcbf217cb280cf30b2517052193ab979"},
    };
    // NIST SP 800-38A F.1.1, ECB-AES128, four consecutive blocks under one key
    static const char *SP800_KEY = "2b7e151628aed2a6abf7158809cf4f3c";
    static const char *SP800_PT =
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
    static const char *SP800_CT =
        "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf"
        "43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4";

    int fails = 0;

    for (size_t i = 0; i < sizeof(SHA_KATS) / sizeof(SHA_KATS[0]); ++i) {
        uint8_t digest[SHA256_DIGEST_SIZE];
        uint8_t expect[SHA256_DIGEST_SIZE];
        sha256((const uint8_t *)SHA_KATS[i].msg, strlen(SHA_KATS[i].msg), digest);
        unhex(SHA_KATS[i].digest, expect);
        int ok = memcmp(digest, expect, SHA256_DIGEST_SIZE) == 0;
        printf("sha256 kat %-46s %s\n", SHA_KATS[i].msg, ok ? "PASS" : "FAIL");
        fails += !ok;
    }

    for (size_t i = 0; i < sizeof(AES_KATS) / sizeof(AES_KATS[0]); ++i) {
        uint8_t key[AES128_KEY_SIZE], pt[AES128_BLOCK_SIZE], ct[AES128_BLOCK_SIZE],
            expect[AES128_BLOCK_SIZE];
        unhex(AES_KATS[i].key, key);
        unhex(AES_KATS[i].pt, pt);
        unhex(AES_KATS[i].ct, expect);
        aes128_ctx ctx;
        aes128_key_expand(&ctx, key);
        aes128_encrypt_block(&ctx, pt, ct);
        int ok = memcmp(ct, expect, AES128_BLOCK_SIZE) == 0;
        printf("aes128 kat %s %s\n", AES_KATS[i].ct, ok ? "PASS" : "FAIL");
        fails += !ok;
    }

    uint8_t key[AES128_KEY_SIZE], pt[64], ct[64], expect[64];
    unhex(SP800_KEY, key);
    size_t ptlen = unhex(SP800_PT, pt);
    unhex(SP800_CT, expect);
    aes128_ctx ctx;
    aes128_key_expand(&ctx, key);
    aes128_encrypt_ecb(&ctx, pt, ptlen, ct);
    int ok = memcmp(ct, expect, ptlen) == 0;
    printf("aes128 sp800-38a ecb x4       %s\n", ok ? "PASS" : "FAIL");
    fails += !ok;

    printf("%s (%d failure%s)\n", fails ? "SELFTEST FAILED" : "all selftests passed", fails,
           fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}

int main(int argc, char *argv[]) {
    sha256_fn fn = sha256;
    const char *impl_name = "scalar";
    int mode = MODE_SHA256;
    int bench = 0;
    int selftest = 0;
    const char *positional[2] = {NULL, NULL};
    int npos = 0;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--neon") == 0) {
            fn = sha256_neon;
            impl_name = "neon";
        } else if (strcmp(argv[i], "--scalar") == 0) {
            fn = sha256;
            impl_name = "scalar";
        } else if (strcmp(argv[i], "--aes") == 0) {
            mode = MODE_AES;
        } else if (strcmp(argv[i], "--sha256") == 0) {
            mode = MODE_SHA256;
        } else if (strcmp(argv[i], "--bench") == 0) {
            bench = 1;
        } else if (strcmp(argv[i], "--selftest") == 0) {
            selftest = 1;
        } else if (npos < 2) {
            positional[npos++] = argv[i];
        } else {
            npos = 3;
            break;
        }
    }

    if (selftest) {
        return run_selftest();
    }

    if (mode == MODE_AES && strcmp(impl_name, "neon") == 0) {
        fprintf(stderr, "--neon is not supported for --aes yet\n");
        return 1;
    }

    if (npos > 2 || (!bench && npos < 1)) {
        printf("Usage: rust-vs-c [--sha256|--aes] [--neon|--scalar] <input string>\n");
        printf("       rust-vs-c --bench [--sha256|--aes] [--neon|--scalar] [input string] [iterations]\n");
        printf("       rust-vs-c --selftest\n");
        return 1;
    }

    const char *msg = positional[0] ? positional[0] : "The quick brown fox jumps over the lazy dog";
    long iters = positional[1] ? atol(positional[1]) : 100000;
    size_t len = strlen(msg);

    if (bench) {
        if (mode == MODE_AES) {
            return run_bench_aes((const uint8_t *)msg, len, iters);
        }
        return run_bench_sha(fn, impl_name, (const uint8_t *)msg, len, iters);
    }

    if (mode == MODE_AES) {
        aes128_ctx ctx;
        aes128_key_expand(&ctx, AES_DEMO_KEY);
        size_t plen = ((len + AES128_BLOCK_SIZE - 1) / AES128_BLOCK_SIZE) * AES128_BLOCK_SIZE;
        if (plen == 0) {
            plen = AES128_BLOCK_SIZE;
        }
        uint8_t *buf = calloc(plen, 1);
        if (!buf) {
            fprintf(stderr, "out of memory\n");
            return 1;
        }
        memcpy(buf, msg, len);
        aes128_encrypt_ecb(&ctx, buf, plen, buf);
        print_hex(buf, plen);
        free(buf);
        return 0;
    }

    uint8_t digest[SHA256_DIGEST_SIZE];
    fn((const uint8_t *)msg, len, digest);
    print_hex(digest, SHA256_DIGEST_SIZE);

    return 0;
}
