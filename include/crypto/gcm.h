#ifndef CRYPTO_GCM_H
#define CRYPTO_GCM_H

#include "crypto_types.h"
#include "AES/AESEncryption.h"
#define GCM_IV_SIZE 12  // 96bit
#define GCM_TAG_SIZE 16 // 128bit
#define GCM_BLOCK_SIZE 16

int aes_gcm_encrypt(const byte *key, const byte *iv, size_t iv_len, const byte *plaintext, size_t pt_len,
                    const byte *add, size_t add_len, byte *ciphertext,byte *tag);

int aes_gcm_decrypt(const byte *key, const byte *iv, size_t iv_len, const byte *ciphertext, size_t ct_len,
                    const byte *aad, size_t aad_len, byte *plaintext,byte *tag);

#endif
