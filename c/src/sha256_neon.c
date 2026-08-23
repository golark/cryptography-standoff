#include "sha256.h"

#include <string.h>

#if defined(__aarch64__) || defined(__arm64__)
#include <arm_neon.h>
#endif

#if !defined(__aarch64__) && !defined(__arm64__)

// Fallback for non-ARM targets so the project still builds elsewhere.
void sha256_neon(const uint8_t *data, size_t len, uint8_t digest[SHA256_DIGEST_SIZE]) {
    sha256(data, len, digest);
}

#else

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

// ARMv8 Crypto Extensions schedule/compress pattern (public domain,
// after Jeffrey Walton / mbedTLS). Each group of 4 rounds interleaves
// vsha256hq/vsha256h2q state updates with vsha256su0q/vsha256su1q
// message-schedule expansion.
static void sha256_process_blocks(uint32_t state[8], const uint8_t *data, size_t nblocks) {
    uint32x4_t STATE0 = vld1q_u32(&state[0]); // {a, b, c, d}
    uint32x4_t STATE1 = vld1q_u32(&state[4]); // {e, f, g, h}

    for (size_t b = 0; b < nblocks; ++b, data += 64) {
        uint32x4_t ABEF_SAVE = STATE0;
        uint32x4_t CDGH_SAVE = STATE1;

        uint32x4_t MSG0 = vld1q_u32((const uint32_t *)(data + 0));
        uint32x4_t MSG1 = vld1q_u32((const uint32_t *)(data + 16));
        uint32x4_t MSG2 = vld1q_u32((const uint32_t *)(data + 32));
        uint32x4_t MSG3 = vld1q_u32((const uint32_t *)(data + 48));

        MSG0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG0)));
        MSG1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG1)));
        MSG2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG2)));
        MSG3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG3)));

        uint32x4_t TMP0 = vaddq_u32(MSG0, vld1q_u32(&K[0x00]));
        uint32x4_t TMP1, TMP2;

        TMP2 = STATE0;
        TMP1 = vaddq_u32(MSG1, vld1q_u32(&K[0x04]));
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG0 = vsha256su1q_u32(vsha256su0q_u32(MSG0, MSG1), MSG2, MSG3);

        TMP2 = STATE0;
        TMP0 = vaddq_u32(MSG2, vld1q_u32(&K[0x08]));
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
        MSG1 = vsha256su1q_u32(vsha256su0q_u32(MSG1, MSG2), MSG3, MSG0);

        TMP2 = STATE0;
        TMP1 = vaddq_u32(MSG3, vld1q_u32(&K[0x0c]));
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG2 = vsha256su1q_u32(vsha256su0q_u32(MSG2, MSG3), MSG0, MSG1);

        TMP2 = STATE0;
        TMP0 = vaddq_u32(MSG0, vld1q_u32(&K[0x10]));
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
        MSG3 = vsha256su1q_u32(vsha256su0q_u32(MSG3, MSG0), MSG1, MSG2);

        TMP2 = STATE0;
        TMP1 = vaddq_u32(MSG1, vld1q_u32(&K[0x14]));
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG0 = vsha256su1q_u32(vsha256su0q_u32(MSG0, MSG1), MSG2, MSG3);

        TMP2 = STATE0;
        TMP0 = vaddq_u32(MSG2, vld1q_u32(&K[0x18]));
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
        MSG1 = vsha256su1q_u32(vsha256su0q_u32(MSG1, MSG2), MSG3, MSG0);

        TMP2 = STATE0;
        TMP1 = vaddq_u32(MSG3, vld1q_u32(&K[0x1c]));
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG2 = vsha256su1q_u32(vsha256su0q_u32(MSG2, MSG3), MSG0, MSG1);

        TMP2 = STATE0;
        TMP0 = vaddq_u32(MSG0, vld1q_u32(&K[0x20]));
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
        MSG3 = vsha256su1q_u32(vsha256su0q_u32(MSG3, MSG0), MSG1, MSG2);

        TMP2 = STATE0;
        TMP1 = vaddq_u32(MSG1, vld1q_u32(&K[0x24]));
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG0 = vsha256su1q_u32(vsha256su0q_u32(MSG0, MSG1), MSG2, MSG3);

        TMP2 = STATE0;
        TMP0 = vaddq_u32(MSG2, vld1q_u32(&K[0x28]));
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
        MSG1 = vsha256su1q_u32(vsha256su0q_u32(MSG1, MSG2), MSG3, MSG0);

        TMP2 = STATE0;
        TMP1 = vaddq_u32(MSG3, vld1q_u32(&K[0x2c]));
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG2 = vsha256su1q_u32(vsha256su0q_u32(MSG2, MSG3), MSG0, MSG1);

        TMP2 = STATE0;
        TMP0 = vaddq_u32(MSG0, vld1q_u32(&K[0x30]));
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
        MSG3 = vsha256su1q_u32(vsha256su0q_u32(MSG3, MSG0), MSG1, MSG2);

        TMP2 = STATE0;
        TMP1 = vaddq_u32(MSG1, vld1q_u32(&K[0x34]));
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

        TMP2 = STATE0;
        TMP0 = vaddq_u32(MSG2, vld1q_u32(&K[0x38]));
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);

        TMP2 = STATE0;
        TMP1 = vaddq_u32(MSG3, vld1q_u32(&K[0x3c]));
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

        TMP2 = STATE0;
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);

        STATE0 = vaddq_u32(STATE0, ABEF_SAVE);
        STATE1 = vaddq_u32(STATE1, CDGH_SAVE);
    }

    vst1q_u32(&state[0], STATE0);
    vst1q_u32(&state[4], STATE1);
}

static const uint32_t H_INIT[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

void sha256_neon(const uint8_t *data, size_t len, uint8_t digest[SHA256_DIGEST_SIZE]) {
    uint32_t state[8];
    memcpy(state, H_INIT, sizeof(state));

    size_t nblocks = len / SHA256_BLOCK_SIZE;
    sha256_process_blocks(state, data, nblocks);

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
    sha256_process_blocks(state, tail, npad);

    for (int i = 0; i < 8; ++i) {
        digest[i * 4] = (uint8_t)(state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(state[i]);
    }
}

#endif
