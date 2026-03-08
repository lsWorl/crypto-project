#include "crypto/gcm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// NIST SP 800-38D Appendix B 测试向量
// 参考：https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf

static int run_gcm_test(const char *name,
                        const byte key[16],
                        const byte iv[12], size_t iv_len,
                        const byte *aad, size_t aad_len,
                        const byte *pt, size_t pt_len,
                        const byte *expected_ct, const byte expected_tag[16])
{
    byte ct[512];
    byte tag[16];
    byte recovered[512];

    aes_gcm_encrypt(key, iv, iv_len, pt, pt_len, aad, aad_len, ct, tag);
    int enc_ok = (memcmp(ct, expected_ct, pt_len) == 0) && (memcmp(tag, expected_tag, 16) == 0);

    int dec_ret = aes_gcm_decrypt(key, iv, iv_len, ct, pt_len, aad, aad_len, recovered, tag);
    int dec_ok = (dec_ret == (int)pt_len) && (memcmp(recovered, pt, pt_len) == 0);

    printf("%s: encrypt=%s decrypt=%s\n", name, enc_ok ? "PASS" : "FAIL", dec_ok ? "PASS" : "FAIL");
    return enc_ok && dec_ok;
}

int main() {
    // Case 1: empty plaintext + empty AAD
    static const byte key1[16] = {0x00};
    static const byte iv1[12] = {0x00};
    static const byte expected_tag1[16] = {
        0x58,0xe2,0xfc,0xce,0xfa,0x7e,0x30,0x61,
        0x36,0x7f,0x1d,0x57,0xa4,0xe7,0x45,0x5a
    };

    // Case 2: 16-byte plaintext
    static const byte key2[16] = {0x00};
    static const byte iv2[12] = {0x00};
    static const byte pt2[16] = {0x00};
    static const byte expected_ct2[16] = {
        0x03,0x88,0xda,0xce,0x60,0xb6,0xa3,0x92,
        0xf3,0x28,0xc2,0xb9,0x71,0xb2,0xfe,0x78
    };
    static const byte expected_tag2[16] = {
        0xab,0x6e,0x47,0xd4,0x2c,0xec,0x13,0xbd,
        0xf5,0x3a,0x67,0xb2,0x12,0x57,0xbd,0xdf
    };

    // Case 3: AAD only
    static const byte key3[16] = {0x00};
    static const byte iv3[12] = {0x00};
    static const byte aad3[16] = {0x00};
    static const byte expected_tag3[16] = {
        0x21,0xc7,0x5a,0xeb,0x2d,0x5e,0x3c,0x3d,
        0x2b,0x3c,0x9c,0x8c,0x0f,0x5c,0x31,0x6b
    };

    int ok = 1;
    ok &= run_gcm_test("NIST Case 1", key1, iv1, 12, NULL, 0, NULL, 0, NULL, expected_tag1);
    ok &= run_gcm_test("NIST Case 2", key2, iv2, 12, NULL, 0, pt2, 16, expected_ct2, expected_tag2);
    ok &= run_gcm_test("NIST Case 3", key3, iv3, 12, aad3, 16, NULL, 0, NULL, expected_tag3);

    if (!ok) {
        printf("至少一个测试用例失败。\n");
        return 1;
    }

    printf("所有 NIST GCM 测试向量通过。\n");
    return 0;
}
