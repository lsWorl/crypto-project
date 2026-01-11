#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "crypto/rng.h"
#include "crypto/crypto_err.h"

int main(void){
    uint8_t a[16];
    uint8_t b[16];
    if(crypto_random_bytes(a, sizeof(a)) != CRYPTO_OK){
        printf("FAIL: crypto_random_bytes failed\n");
        return 2;
    }
    if(crypto_random_bytes(b, sizeof(b)) != CRYPTO_OK){
        printf("FAIL: crypto_random_bytes failed (second call)\n");
        return 2;
    }
    if(memcmp(a,b,sizeof(a))==0){
        printf("WARN: two generated blocks are equal (unlikely)\n");
    } else {
        printf("OK: RNG produced two different outputs\n");
    }
    return 0;
}
