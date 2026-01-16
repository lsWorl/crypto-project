#ifndef KDF_H
#define KDF_H

#include "crypto_types.h"



// byte k_etm_encrypt[16];     // AES-ETM 加密密钥
// byte k_etm_hmac[32];        // AES-ETM HMAC密钥
// byte k_gcm_encrypt[16];     // AES-GCM加密密钥
// byte k_gcm_hmac[32];        // AES-GCM HMAC密钥
// byte nonce_seed[32];        // AES-GCM随机数种子

// 函数声明
void pbkdf2_hmac_sha256(const byte *password, size_t password_len,
                         const byte *salt, size_t salt_len,
                         int iterations, size_t dk_len, byte *out_dk);

void HKDF_SHA256(const byte *ikm, size_t ikm_len,
                   const byte *salt, size_t salt_len,
                   const byte *info, size_t info_len,
                   size_t okm_len, byte *out_okm);

#endif // KDF_H