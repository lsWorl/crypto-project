#ifndef CRYPTO_HMAC_H
#define CRYPTO_HMAC_H

#include "sha256.h"
#include <string.h>
#include <stdlib.h>

#define HMAC_BLOCK_SIZE 64  // SHA-256 block size in bytes
#define HMAC_HASH_SIZE SHA256_HASH_SIZE

// HMAC-SHA256函数声明
void hmac_sha256(const byte *key, size_t key_len,
                 const byte *message, size_t message_len,
                 byte *out_digest);

#endif // CRYPTO_HMAC_H