#ifndef AES_DECRYPTION_H
#define AES_DECRYPTION_H

#include "common.h"
#include "crypto/aes.h"
#include "crypto/hmac.h"
// The function declarations are provided by crypto/aes.h.
// Keep this file for backwards compatibility and internal includes.
int decrypt_etm(byte Ciperkey[16],byte Mackey[32], byte *input, size_t input_len, byte *output);
int decrypt_file_etm(const char *input_filename, const char *output_filename, byte Ciperkey[16], byte Mackey[32]);
#endif // AES_DECRYPTION_H