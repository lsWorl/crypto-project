#include "crypto/hmac.h"
#include "vectors.h"
#include <string.h>
#include <stdio.h>

static void to_hex(const byte *digest, char *out)
{
    for (int i = 0; i < SHA256_HASH_SIZE; i++)
    {
        sprintf(out + i * 2, "%02x", digest[i]);
    }
    out[SHA256_HASH_SIZE * 2] = '\0';
}

static void print_hex(const byte *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

static int test_vector(const byte *key, size_t key_len,
                       const byte *msg, size_t msg_len,
                       const char *expected_hex, const char *case_name)
{
    byte digest[HMAC_HASH_SIZE];
    hmac_sha256(key, key_len, msg, msg_len, digest);
    char hex[HMAC_HASH_SIZE * 2 + 1];
    to_hex(digest, hex);
    if (strcmp(hex, expected_hex) == 0)
    {
        printf("PASS: HMAC-SHA256 %s\n", case_name);
        return 0;
    }
    else
    {
        printf("FAIL: %s\n got %s\n expected %s\n", case_name, hex, expected_hex);
        return 1;
    }
}

// 调试用：打印 i_key_pad, inner_hash 和最终 HMAC
static void debug_hmac_case(const byte *key, size_t key_len,
                            const byte *msg, size_t msg_len)
{
    byte key_block[HMAC_BLOCK_SIZE];
    if (key_len > HMAC_BLOCK_SIZE)
    {
        sha256(key, key_len, key_block);
        memset(key_block + HMAC_HASH_SIZE, 0, HMAC_BLOCK_SIZE - HMAC_HASH_SIZE);
    }
    else
    {
        memcpy(key_block, key, key_len);
        memset(key_block + key_len, 0, HMAC_BLOCK_SIZE - key_len);
    }

    byte i_key_pad[HMAC_BLOCK_SIZE];
    byte o_key_pad[HMAC_BLOCK_SIZE];
    for (size_t i = 0; i < HMAC_BLOCK_SIZE; i++)
    {
        i_key_pad[i] = key_block[i] ^ 0x36;
        o_key_pad[i] = key_block[i] ^ 0x5c;
    }

    printf("i_key_pad: ");
    print_hex(i_key_pad, HMAC_BLOCK_SIZE);

    // inner hash
    byte *inner_data = (byte *)malloc(HMAC_BLOCK_SIZE + msg_len);
    memcpy(inner_data, i_key_pad, HMAC_BLOCK_SIZE);
    memcpy(inner_data + HMAC_BLOCK_SIZE, msg, msg_len);
    byte inner_hash[HMAC_HASH_SIZE];
    sha256(inner_data, HMAC_BLOCK_SIZE + msg_len, inner_hash);
    free(inner_data);

    printf("inner_hash: ");
    print_hex(inner_hash, HMAC_HASH_SIZE);

    // outer
    byte outer_data[HMAC_BLOCK_SIZE + HMAC_HASH_SIZE];
    memcpy(outer_data, o_key_pad, HMAC_BLOCK_SIZE);
    memcpy(outer_data + HMAC_BLOCK_SIZE, inner_hash, HMAC_HASH_SIZE);
    byte final[HMAC_HASH_SIZE];
    sha256(outer_data, HMAC_BLOCK_SIZE + HMAC_HASH_SIZE, final);

    printf("final_hmac: ");
    print_hex(final, HMAC_HASH_SIZE);
}

int main()
{
    int failures = 0;

    // 测试向量来自RFC 4231
    for (size_t i = 0; i < HMAC_SHA256_VECTOR_COUNT; i++)
    {
        const struct hmac_test_vector *vec = &HMAC_SHA256_VECTORS[i];
        failures += test_vector(vec->key, vec->key_len,
                                vec->msg, vec->msg_len,
                                vec->expected_hex, vec->name);
    }

    if (failures != 0)
    {
        printf("\n--- Debug info for failed vectors ---\n");
        printf("Case 1 (key=0x0b*20, msg=\"Hi There\"):\n");
        debug_hmac_case(HMAC_KEY_1, sizeof(HMAC_KEY_1),
                        HMAC_MSG_1, 8);
        printf("\nCase 3 (key=0xaa*20, msg=0xdd*50):\n");
        debug_hmac_case(HMAC_KEY_3, sizeof(HMAC_KEY_3),
                        HMAC_MSG_3, 50);
        printf("--- End debug info ---\n\n");
    }

    if (failures == 0)
    {
        printf("All tests passed\n");
    }
    else
    {
        printf("Some tests failed\n");
    }
    return failures;
}