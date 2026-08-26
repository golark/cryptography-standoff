#ifndef AES128_H
#define AES128_H

#include <stddef.h>
#include <stdint.h>

#define AES128_BLOCK_SIZE 16
#define AES128_KEY_SIZE 16
#define AES128_ROUNDS 10

typedef struct {
    uint32_t rk[4 * (AES128_ROUNDS + 1)];
} aes128_ctx;

void aes128_key_expand(aes128_ctx *ctx, const uint8_t key[AES128_KEY_SIZE]);

void aes128_encrypt_block(const aes128_ctx *ctx, const uint8_t in[AES128_BLOCK_SIZE],
                          uint8_t out[AES128_BLOCK_SIZE]);

// ECB mode; len must be a multiple of AES128_BLOCK_SIZE.
void aes128_encrypt_ecb(const aes128_ctx *ctx, const uint8_t *in, size_t len, uint8_t *out);

// ARMv8 Crypto Extensions variants (fall back to scalar on non-ARM targets).
void aes128_encrypt_block_neon(const aes128_ctx *ctx, const uint8_t in[AES128_BLOCK_SIZE],
                               uint8_t out[AES128_BLOCK_SIZE]);
void aes128_encrypt_ecb_neon(const aes128_ctx *ctx, const uint8_t *in, size_t len, uint8_t *out);

#endif
