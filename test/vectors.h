#ifndef TEST_VECTORS_H
#define TEST_VECTORS_H

#include "common.h"
#include <stddef.h>

static const byte AES128_KEY[STATE_SIZE] = {
    0x2b, 0x7e, 0x15, 0x16,
    0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88,
    0x09, 0xcf, 0x4f, 0x3c
};

static const byte AES128_PLAINTEXT[STATE_SIZE] = {
    0x32, 0x43, 0xf6, 0xa8,
    0x88, 0x5a, 0x30, 0x8d,
    0x31, 0x31, 0x98, 0xa2,
    0xe0, 0x37, 0x07, 0x34
};

static const byte AES128_CIPHERTEXT[STATE_SIZE] = {
    0x39, 0x25, 0x84, 0x1d,
    0x02, 0xdc, 0x09, 0xfb,
    0xdc, 0x11, 0x85, 0x97,
    0x19, 0x6a, 0x0b, 0x32
};

struct hmac_test_vector {
    const char *name;
    const byte *key;
    size_t key_len;
    const byte *msg;
    size_t msg_len;
    const char *expected_hex;
};

static const byte HMAC_KEY_1[] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};
static const byte HMAC_MSG_1[] = "Hi There";

static const byte HMAC_KEY_2[] = "Jefe";
static const byte HMAC_MSG_2[] = "what do ya want for nothing?";

static const byte HMAC_KEY_3[] = {
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa
};
static const byte HMAC_MSG_3[] = {
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd
};

static const struct hmac_test_vector HMAC_SHA256_VECTORS[] = {
    {
        "RFC4231 Case 1",
        HMAC_KEY_1, sizeof(HMAC_KEY_1),
        HMAC_MSG_1, 8,
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    },
    {
        "RFC4231 Case 2",
        HMAC_KEY_2, 4,
        HMAC_MSG_2, 28,
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    },
    {
        "RFC4231 Case 3",
        HMAC_KEY_3, sizeof(HMAC_KEY_3),
        HMAC_MSG_3, 50,
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
    }
};

// 测试向量数量
static const size_t HMAC_SHA256_VECTOR_COUNT =
    sizeof(HMAC_SHA256_VECTORS) / sizeof(HMAC_SHA256_VECTORS[0]);


struct pbkdf2_test_vector {
    const char *password;
    const byte *salt;
    size_t salt_len;
    int iterations;
    size_t dk_len;
    const char *expected_hex;
};

static const struct pbkdf2_test_vector PBKDF2_SHA256_VECTORS[] = {
    {
        "passwd",
        (const byte *)"salt", 4,
        1,
        64,
        "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
    },
    {
        "Password",
        (const byte *)"NaCl", 4,
        80000,
        64,
        "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"
    }
};

static const size_t PBKDF2_SHA256_VECTOR_COUNT =
    sizeof(PBKDF2_SHA256_VECTORS) / sizeof(PBKDF2_SHA256_VECTORS[0]);


struct hkdf_test_vector {
    const byte *ikm;
    size_t ikm_len;
    const byte *salt;
    size_t salt_len;
    const byte *info;
    size_t info_len;
    size_t okm_len;
    const char *expected_hex;
};

static const byte HKDF_T1_IKM[] = {
    0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
    0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
    0x0b,0x0b
};
static const byte HKDF_T1_SALT[] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c
};
static const byte HKDF_T1_INFO[] = {
    0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9
};

static const byte HKDF_T3_IKM[] = {
    0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
    0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
    0x0b,0x0b
};

static const struct hkdf_test_vector HKDF_SHA256_VECTORS[] = {
    /* Test Case 1 (RFC 5869 A.1) */
    {
        HKDF_T1_IKM, sizeof(HKDF_T1_IKM),
        HKDF_T1_SALT, sizeof(HKDF_T1_SALT),
        HKDF_T1_INFO, sizeof(HKDF_T1_INFO),
        42,
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    },

    /* Test Case 3 (RFC 5869 A.3) - no salt, no info */
    {
        HKDF_T3_IKM, sizeof(HKDF_T3_IKM),
        NULL, 0,
        NULL, 0,
        42,
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    }
};

#endif // TEST_VECTORS_H