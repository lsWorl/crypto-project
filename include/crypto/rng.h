#ifndef CRYPTO_RNG_H
#define CRYPTO_RNG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int crypto_random_bytes(uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif // CRYPTO_RNG_H
