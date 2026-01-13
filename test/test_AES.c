#include "common.h"
#include "AESEncryption.h"
#include "AESDecryption.h"
int main(void) {
    // 对应论文地址为https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
    // 状态向量采用Appendix B中的测试向量
    byte input[STATE_SIZE] = {
        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2,
        0xe0, 0x37, 0x07, 0x34
    };
    
    byte key[STATE_SIZE] = {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c
    };
    
    byte output[STATE_SIZE];
    
    encrypt(key, input, output);
    
    printf("Encrypted output:\n");
    for(int i = 0; i < STATE_SIZE; i++) {
        printf("%02x ", output[i]);
    }
    printf("\n");
    
    decrypt(key, output, input);
    printf("Decrypted output:\n");
    for(int i = 0; i < STATE_SIZE; i++) {
        printf("%02x ", input[i]);
    }
    printf("\n");

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