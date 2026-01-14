#ifndef RNG_H
#define RNG_H
#include "crypto_types.h"

//函数声明
int crypto_random_bytes(byte *buf, size_t len);

#endif // RNG_H