#include <stdio.h>
#include <string.h>

#include "sha256.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: rust-vs-c <input string>\n");
        return 1;
    }

    const uint8_t *input = (const uint8_t *)argv[1];
    size_t len = strlen(argv[1]);

    uint8_t digest[SHA256_DIGEST_SIZE];
    sha256(input, len, digest);

    for (int i = 0; i < SHA256_DIGEST_SIZE; ++i) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    return 0;
}
