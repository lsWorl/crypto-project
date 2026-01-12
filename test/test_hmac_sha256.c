#include "hmac.h"
#include <string.h>
#include <stdio.h>

static void to_hex(const byte *digest, char *out) {
    for (int i = 0; i < SHA256_HASH_SIZE; i++) {
        sprintf(out + i * 2, "%02x", digest[i]);
    }
    out[SHA256_HASH_SIZE * 2] = '\0';
}

static void print_hex(const byte *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}



static int test_vector(const byte *key, size_t key_len,
                       const byte *msg, size_t msg_len,
                       const char *expected_hex) {
    byte digest[HMAC_HASH_SIZE];
    hmac_sha256(key, key_len, msg, msg_len, digest);
    char hex[HMAC_HASH_SIZE * 2 + 1];
    to_hex(digest, hex);
    if (strcmp(hex, expected_hex) == 0) {
        printf("PASS: HMAC-SHA256\n");
        return 0;
    } else {
        printf("FAIL: got %s\nexpected %s\n", hex, expected_hex);
        return 1;
    }
}

// 调试用：打印 i_key_pad, inner_hash 和最终 HMAC
static void debug_hmac_case(const byte *key, size_t key_len,
                            const byte *msg, size_t msg_len) {
    byte key_block[HMAC_BLOCK_SIZE];
    if (key_len > HMAC_BLOCK_SIZE) {
        sha256(key, key_len, key_block);
        memset(key_block + HMAC_HASH_SIZE, 0, HMAC_BLOCK_SIZE - HMAC_HASH_SIZE);
    } else {
        memcpy(key_block, key, key_len);
        memset(key_block + key_len, 0, HMAC_BLOCK_SIZE - key_len);
    }

    byte i_key_pad[HMAC_BLOCK_SIZE];
    byte o_key_pad[HMAC_BLOCK_SIZE];
    for (size_t i = 0; i < HMAC_BLOCK_SIZE; i++) {
        i_key_pad[i] = key_block[i] ^ 0x36;
        o_key_pad[i] = key_block[i] ^ 0x5c;
    }

    printf("i_key_pad: "); print_hex(i_key_pad, HMAC_BLOCK_SIZE);

    // inner hash
    byte *inner_data = (byte*)malloc(HMAC_BLOCK_SIZE + msg_len);
    memcpy(inner_data, i_key_pad, HMAC_BLOCK_SIZE);
    memcpy(inner_data + HMAC_BLOCK_SIZE, msg, msg_len);
    byte inner_hash[HMAC_HASH_SIZE];
    sha256(inner_data, HMAC_BLOCK_SIZE + msg_len, inner_hash);
    free(inner_data);

    printf("inner_hash: "); print_hex(inner_hash, HMAC_HASH_SIZE);

    // outer
    byte outer_data[HMAC_BLOCK_SIZE + HMAC_HASH_SIZE];
    memcpy(outer_data, o_key_pad, HMAC_BLOCK_SIZE);
    memcpy(outer_data + HMAC_BLOCK_SIZE, inner_hash, HMAC_HASH_SIZE);
    byte final[HMAC_HASH_SIZE];
    sha256(outer_data, HMAC_BLOCK_SIZE + HMAC_HASH_SIZE, final);

    printf("final_hmac: "); print_hex(final, HMAC_HASH_SIZE);
}

int main(int argc, char **argv) {
    int failures = 0;

    // 测试向量来自RFC 4231
failures += test_vector((const byte*)"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 20,
                            (const byte*)"Hi There", 8,
                            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    failures += test_vector((const byte*)"Jefe", 4,
                            (const byte*)"what do ya want for nothing?", strlen("what do ya want for nothing?"),
                            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
failures += test_vector((const byte*)"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 20,
                            (const byte*)"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd", 50,
                            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");

    if (failures != 0) {
        printf("\n--- Debug info for failed vectors ---\n");
        printf("Case 1 (key=0x0b*20, msg=\"Hi There\"):\n");
        debug_hmac_case((const byte*)"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 20,
                        (const byte*)"Hi There", 8);
        printf("\nCase 3 (key=0xaa*20, msg=0xdd*50):\n");
debug_hmac_case((const byte*)"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 20,
                        (const byte*)"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd", 50);
        printf("--- End debug info ---\n\n");
    }

    if (failures == 0) {
        printf("All tests passed\n");
    } else {
        printf("Some tests failed\n");
    }
    return failures;
}