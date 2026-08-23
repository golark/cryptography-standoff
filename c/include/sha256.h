#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

void sha256(const uint8_t *data, size_t len, uint8_t digest[SHA256_DIGEST_SIZE]);

// ARMv8 Crypto Extensions variant (falls back to scalar on non-ARM targets).
void sha256_neon(const uint8_t *data, size_t len, uint8_t digest[SHA256_DIGEST_SIZE]);

#endif
