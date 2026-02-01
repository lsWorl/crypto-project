#ifndef CRYPTO_CRYPTO_TYPES_H
#define CRYPTO_CRYPTO_TYPES_H

#include <stddef.h>
#include <stdint.h>

typedef unsigned char byte;

//AES相关常量
#define Nb 4           //列数
#define Nk 4           //密钥长度,以32位字为单位,故当前密钥长度为128位
#define Nr 10          //轮数
#define STATE_SIZE 16  //状态矩阵大小
#define BLOCK_SIZE 16  //块大小

// AES-ETM相关常量
#define ETM_IV_SIZE 16 // IV大小
#define ETM_HMAC_SIZE 32 // HMAC大小
#define ETM_OVERHEAD (ETM_IV_SIZE + ETM_HMAC_SIZE) // IV和HMAC总大小

// PBKDF2相关常量
#define PBKDF2_SALT_SIZE 16
#define PBKDF2_ITERATIONS 100000  //先固定迭代次数为100000次

// 密钥派生相关常量
#define MASTER_KEY_SIZE 32
#define AES_KEY_SIZE 16
#define HMAC_KEY_SIZE 32
#define NOUNCE_SEED_SIZE 32

// HKDF相关常量
#define HKDF_HASH_SIZE 32 // SHA-256 输出大小


// HMAC相关常量
#define HMAC_BLOCK_SIZE 64  // SHA-256 block size in bytes
#define HMAC_HASH_SIZE SHA256_HASH_SIZE

// SHA-256相关常量
#define SHA256_BLOCK_SIZE 64 // 每次处理 512 bit = 64 字节
#define SHA256_HASH_SIZE 32  // 输出 256 bit = 32 字节

#define SALT_SIZE 16


//ECC 相关常量
#define X25519_KEY_SIZE 32      //私钥公钥共享密钥均为32B
#define CURVE25519_P_BYTES 32  //域大小为256bit

typedef int64_t field_elem[16]; // 用于表示25519域元素
#endif // CRYPTO_CRYPTO_TYPES_H