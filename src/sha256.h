#ifndef SHA256_H
#define SHA256_H
#include "common.h"
#include <stdint.h>
#include <stddef.h>


#define SHA256_BLOCK_SIZE 64 // 每次处理 512 bit = 64 字节
#define SHA256_HASH_SIZE 32  // 输出 256 bit = 32 字节

// 初始哈希值（素数 2,3,5,7,11,13,17,19 的平方根小数部分的前 32 位）
extern const uint32_t sha256_initial_hash[8];

// 轮常量（素数 2,3,5,7,11,... 的立方根小数部分的前 32 位）
extern const uint32_t sha256_round_constants[64];

// 函数声明
void sha256(const byte *input, size_t input_len, byte *digest);
void sha256_print(const byte *digest);
#endif