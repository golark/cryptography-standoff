#include "sha256.h"

#include <string.h>

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

// FIPS 180-4 section 4.1.2
#define SIGMA0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIGMA1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))
#define EPS0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EPS1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

// First 32 bits of the fractional parts of the square roots of the first
// 8 primes (FIPS 180-4 section 5.3.3)
static const uint32_t H_INIT[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

// First 32 bits of the fractional parts of the cube roots of the first
// 64 primes (FIPS 180-4 section 4.2.2)
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static void sha256_compress(uint32_t state[8], const uint8_t *block) {
    uint32_t W[64];

    for (int t = 0; t < 16; ++t) {
        W[t] = ((uint32_t)block[t * 4] << 24) |
               ((uint32_t)block[t * 4 + 1] << 16) |
               ((uint32_t)block[t * 4 + 2] << 8) |
               (uint32_t)block[t * 4 + 3];
    }
    for (int t = 16; t < 64; ++t) {
        W[t] = SIGMA1(W[t - 2]) + W[t - 7] + SIGMA0(W[t - 15]) + W[t - 16];
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int t = 0; t < 64; ++t) {
        uint32_t T1 = h + EPS1(e) + CH(e, f, g) + K[t] + W[t];
        uint32_t T2 = EPS0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void sha256(const uint8_t *data, size_t len, uint8_t digest[SHA256_DIGEST_SIZE]) {
    uint32_t state[8];
    for (int i = 0; i < 8; ++i) {
        state[i] = H_INIT[i];
    }

    size_t nblocks = len / SHA256_BLOCK_SIZE;
    for (size_t i = 0; i < nblocks; ++i) {
        sha256_compress(state, data + i * SHA256_BLOCK_SIZE);
    }

    // Padding: msg || 0x80 || zeros || 64-bit BE bit-length (FIPS 180-4 5.1.1)
    size_t rem = len % SHA256_BLOCK_SIZE;
    uint8_t tail[2 * SHA256_BLOCK_SIZE];
    memset(tail, 0, sizeof(tail));
    memcpy(tail, data + nblocks * SHA256_BLOCK_SIZE, rem);
    tail[rem] = 0x80;

    size_t npad = (rem < 56) ? 1 : 2;
    uint64_t bit_len = (uint64_t)len * 8;
    for (int i = 0; i < 8; ++i) {
        tail[npad * SHA256_BLOCK_SIZE - 1 - i] = (uint8_t)(bit_len >> (8 * i));
    }
    for (size_t i = 0; i < npad; ++i) {
        sha256_compress(state, tail + i * SHA256_BLOCK_SIZE);
    }

    for (int i = 0; i < 8; ++i) {
        digest[i * 4] = (uint8_t)(state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(state[i]);
    }
}
