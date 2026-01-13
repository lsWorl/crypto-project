#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sha256.h"

static void to_hex(const byte *digest, char *out) {
    for (int i = 0; i < SHA256_HASH_SIZE; i++) {
        sprintf(out + i * 2, "%02x", digest[i]);
    }
    out[SHA256_HASH_SIZE * 2] = '\0';
}

static int test_vector(const byte *msg, size_t msg_len, const char *expected_hex) {
    byte digest[SHA256_HASH_SIZE];
    sha256(msg, msg_len, digest);
    char hex[SHA256_HASH_SIZE * 2 + 1];  //65字节，最后一个字节存放结束符
    to_hex(digest, hex);
    if (strcmp(hex, expected_hex) == 0) {
        printf("PASS: (%zu bytes) %s\n", msg_len, expected_hex);
        return 0;
    } else {
        printf("FAIL: got %s\nexpected %s\n", hex, expected_hex);
        return 1;
    }
}

int main() {
    int failures = 0;

    failures += test_vector((const byte*)"", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    failures += test_vector((const byte*)"abc", 3, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    failures += test_vector((const byte*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                             strlen("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
                             "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");


    if (failures == 0) {
        printf("All tests passed\n");
    } else {
        printf("Some tests failed\n");
    }

    return failures;
}
