#ifndef FILE_CRYPTO_H
#define FILE_CRYPTO_H
#include "crypto_types.h"

int encrypt_file_HKDF(const char *input_path, const char *output_path, const char *password, size_t pass_len, size_t iterations);
int decrypt_file_HKDF(const char *input_path, const char *output_path, const char *password, size_t pass_len);

#endif // FILE_CRYPTO_H