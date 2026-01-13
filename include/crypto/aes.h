#ifndef CRYPTO_AES_H
#define CRYPTO_AES_H

#include <stdint.h>
#include <stddef.h>
#include "crypto_types.h"
#ifdef __cplusplus
extern "C" {
#endif

// Block-level AES functions (128-bit key assumed in current project)
void encrypt(byte key[16], byte input[16], byte output[16]);
void decrypt(byte key[16], byte input[16], byte output[16]);

// CBC helpers
void encrypt_cbc(byte key[16], byte iv[16], byte *input, byte *output, int length);
void decrypt_cbc(byte key[16], byte iv[16], byte *input, byte *output, int length);

// File helpers
void encrypt_file(const char *input_filename, const char *output_filename, byte key[16]);
void decrypt_file(const char *input_filename, const char *output_filename, byte key[16]);

#ifdef __cplusplus
}
#endif

#endif // CRYPTO_AES_H
