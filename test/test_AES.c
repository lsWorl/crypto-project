#include "common.h"
#include "AESEncryption.h"
#include "AESDecryption.h"
#include "vectors.h"
#include <string.h>
int main(void) {
    // 对应论文地址为https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
    // 状态向量采用Appendix B中的测试向量
    byte input[STATE_SIZE];
    byte key[STATE_SIZE];
    byte output[STATE_SIZE];
    memcpy(input, AES128_PLAINTEXT, STATE_SIZE);
    memcpy(key, AES128_KEY, STATE_SIZE);
    encrypt(key, input, output);
    
    printf("Encrypted output:\n");
    for(int i = 0; i < STATE_SIZE; i++) {
        printf("%02x ", output[i]);
    }
    printf("\n");
    if(memcmp(output, AES128_CIPHERTEXT, STATE_SIZE) == 0) {
        printf("PASS: AES-128 test vector\n");
    } else {
        printf("FAIL: AES-128 test vector\n");
    }
    decrypt(key, output, input);
    printf("Decrypted output:\n");
    for(int i = 0; i < STATE_SIZE; i++) {
        printf("%02x ", input[i]);
    }
    printf("\n");

    if(memcmp(input, AES128_PLAINTEXT, STATE_SIZE) == 0) {
        printf("PASS: AES-128 decryption test vector\n");
    } else {
        printf("FAIL: AES-128 decryption test vector\n");
    }

    // ---------- 文件加密演示 ----------
    const char *plaintext = "sample_plain.txt";
    const char *cipherfile = "sample_encrypted.aes";
    encrypt_file(plaintext, cipherfile, key);
    printf("File encrypted to '%s'\n", cipherfile);

    // 打印文件大小以做基本验证
    FILE *fplain = fopen(plaintext, "rb");
    FILE *fcipher = fopen(cipherfile, "rb");
    if (fplain && fcipher) {
        fseek(fplain, 0, SEEK_END);
        long plain_size = ftell(fplain);
        fseek(fplain, 0, SEEK_SET);
        fseek(fcipher, 0, SEEK_END);
        long cipher_size = ftell(fcipher);
        fseek(fcipher, 0, SEEK_SET);
        printf("Plain size: %ld, Cipher size: %ld\n", plain_size, cipher_size);
        fclose(fplain);
        fclose(fcipher);
    }

    // ---------- 文件解密演示 ----------
    const char *decryptedfile = "sample_encrypted.aes";
    const char *outputfile = "sample_decrypted.txt";
    decrypt_file(decryptedfile, outputfile, key);
    printf("File decrypted to '%s'\n", outputfile);

    return 0;
}