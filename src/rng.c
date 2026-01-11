#include "crypto/rng.h"
#include "crypto/crypto_err.h"

#include <stdlib.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h> // link with -lbcrypt
#else
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#endif

// Secure platform RNG. On Windows use BCryptGenRandom; otherwise read from /dev/urandom.
int crypto_random_bytes(uint8_t *buf, size_t len){
    if(!buf) return CRYPTO_ERR_INVALID_ARG;
#ifdef _WIN32
    NTSTATUS status = BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if(!BCRYPT_SUCCESS(status)) return CRYPTO_ERR_RNG;
    return CRYPTO_OK;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if(fd < 0) return CRYPTO_ERR_RNG;
    ssize_t rd = read(fd, buf, len);
    close(fd);
    if(rd != (ssize_t)len) return CRYPTO_ERR_RNG;
    return CRYPTO_OK;
#endif
}
