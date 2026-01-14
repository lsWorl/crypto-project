#include "crypto/kdf.h"
#include "AES/common.h"
#include "vectors.h"
#include <string.h>
#include <stdio.h>

int main(void){
    // debug: startup message to verify execution
    printf("Running test_kdf\n");
    // 使用测试向量验证 PBKDF2-HMAC-SHA256 实现
    int failures = 0;
    size_t vector_count = sizeof(PBKDF2_SHA256_VECTORS) / sizeof(PBKDF2_SHA256_VECTORS[0]);
    printf("PBKDF2 vector count: %zu\n", vector_count);
    for (size_t i = 0; i < sizeof(PBKDF2_SHA256_VECTORS) / sizeof(PBKDF2_SHA256_VECTORS[0]); i++)
    {
        const struct pbkdf2_test_vector *vec = &PBKDF2_SHA256_VECTORS[i];
        byte derived_key[64]; // 假设最大派生密钥长度为64字节
        memset(derived_key, 0, sizeof(derived_key));

        pbkdf2_hmac_sha256((const byte *)vec->password, strlen(vec->password),
                           vec->salt, vec->salt_len,
                           vec->iterations, vec->dk_len, derived_key);

        char derived_hex[128]; // 每字节2字符 + 终止符
        for (size_t j = 0; j < vec->dk_len; j++)
        {
            sprintf(&derived_hex[j * 2], "%02x", derived_key[j]);
        }
        derived_hex[vec->dk_len * 2] = '\0';

        if (strcmp(derived_hex, vec->expected_hex) == 0)
        {
            printf("PASS: PBKDF2-SHA256 %s\n", vec->password);
        }
        else
        {
            printf("FAIL: PBKDF2-SHA256 %s\n got %s\n expected %s\n",
                   vec->password, derived_hex, vec->expected_hex);
            failures++;
        }
    }
    printf("\n");

    // 使用测试向量验证 HKDF-SHA256（RFC5869）实现
    size_t hkdf_count = sizeof(HKDF_SHA256_VECTORS) / sizeof(HKDF_SHA256_VECTORS[0]);
    printf("HKDF vector count: %zu\n", hkdf_count);
    for (size_t i = 0; i < hkdf_count; i++) {
        const struct hkdf_test_vector *vec = &HKDF_SHA256_VECTORS[i];
        byte okm[256]; // 足够大的缓冲
        memset(okm, 0, sizeof(okm));

        HKDF_SHA256(vec->ikm, vec->ikm_len,
                    vec->salt, vec->salt_len,
                    vec->info, vec->info_len,
                    vec->okm_len, okm);

        char okm_hex[512];
        for (size_t j = 0; j < vec->okm_len; j++) {
            sprintf(&okm_hex[j * 2], "%02x", okm[j]);
        }
        okm_hex[vec->okm_len * 2] = '\0';

        if (strcmp(okm_hex, vec->expected_hex) == 0) {
            printf("PASS: HKDF-SHA256 test %zu\n", i + 1);
        } else {
            printf("FAIL: HKDF-SHA256 test %zu\n got %s\n expected %s\n",
                   i + 1, okm_hex, vec->expected_hex);
            failures++;
        }
    }

    printf("\n");

    return failures;
}