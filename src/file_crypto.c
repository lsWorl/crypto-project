// 文件格式为ITERATIONS || SALT ||（ IV || CIPHERTEXT || TAG） IV密钥TAG均在encrypt_etm函数中生成
#include <stdio.h>

#include "crypto/file_crypto.h"
#include "crypto/rng.h"
#include "crypto/kdf.h"
#include "crypto/hmac.h"
#include "AES/common.h"
#include "AES/AESEncryption.h"
#include "AES/AESDecryption.h"
int encrypt_file_HKDF(const char *input_path, const char *output_path, const char *password, size_t pass_len, size_t iterations)
{
    // 生成随机盐值
    byte salt[SALT_SIZE];
    crypto_random_bytes(salt, SALT_SIZE);
    // 生成PBKDF2 Master Key
    byte master_key[MASTER_KEY_SIZE];
    pbkdf2_hmac_sha256((const byte *)password, pass_len,
                       salt, SALT_SIZE,
                       iterations, MASTER_KEY_SIZE, master_key);


    // HKDF 派生密钥
    byte k_etm_encrypt[AES_KEY_SIZE]; // AES-ETM 加密
    byte k_etm_hmac[HMAC_KEY_SIZE];   // AES-ETM HMAC密钥
    HKDF_SHA256(master_key, MASTER_KEY_SIZE,
                salt, SALT_SIZE,
                (byte *)"enc_key", 7,
                AES_KEY_SIZE,
                k_etm_encrypt);
    HKDF_SHA256(master_key, MASTER_KEY_SIZE,
                salt, SALT_SIZE,
                (byte *)"hmac_key", 8,
                HMAC_KEY_SIZE,
                k_etm_hmac);
    
    byte iv[16];
    crypto_random_bytes(iv, 16);
    //文件
    FILE *fin = fopen(input_path, "rb");
    FILE *fout = fopen(output_path, "wb");
    if(fin == NULL || fout == NULL){
        if(fin) fclose(fin);
        if(fout) fclose(fout);
        printf("Error opening files.\n");
        return -1; // 文件打开失败
    }

    fseek(fin, 0, SEEK_END);
    size_t input_len = ftell(fin);
    fseek(fin, 0, SEEK_SET);

    byte *input_buf = (byte *)malloc(input_len);
    fread(input_buf, 1, input_len, fin);
    fclose(fin);
    
    // AES-ETM加密
    int max_out = input_len + BLOCK_SIZE + ETM_OVERHEAD; // 包括填充
    byte *output_buf = (byte *)malloc(max_out);

    int output_len = encrypt_etm(k_etm_encrypt, k_etm_hmac, iv, input_buf, input_len, output_buf);
    if(output_len < 0){
        free(input_buf);
        free(output_buf);
        printf("Encryption failed\n");
        return -1; // 加密失败
    }
    // 先写入迭代次数和盐值
    byte iter_bytes[4]; // 大端存储
    iter_bytes[0] = (iterations >> 24) & 0xFF;
    iter_bytes[1] = (iterations >> 16) & 0xFF;
    iter_bytes[2] = (iterations >> 8) & 0xFF;
    iter_bytes[3] = iterations & 0xFF;
    fwrite(iter_bytes, 1, 4, fout);
    fwrite(salt, 1, SALT_SIZE, fout);
    // fwrite(iv, 1, ETM_IV_SIZE, fout);
    fwrite(output_buf, 1, output_len, fout);
    fclose(fout);

    free(input_buf);
    free(output_buf);

    return 0;
}

int decrypt_file_HKDF(const char *input_path, const char *output_path, const char *password, size_t pass_len)
{
    FILE *fin = fopen(input_path, "rb");
    if(fin == NULL){
        return -1; // 文件打开失败
    }
    // 读取迭代次数和盐值
    byte iter_bytes[4];
    byte salt[SALT_SIZE];
    fread(iter_bytes, 1, 4, fin);
    fread(salt, 1, SALT_SIZE, fin);
    size_t iterations = (iter_bytes[0] << 24) | (iter_bytes[1] << 16) | (iter_bytes[2] << 8) | iter_bytes[3];

    fseek(fin, 0, SEEK_END);
    size_t file_len = ftell(fin);
    fseek(fin, 4 + SALT_SIZE, SEEK_SET); // 跳过迭代次数和盐值

    size_t etm_len = file_len - (4 + SALT_SIZE);
    byte *etm_buf = (byte *)malloc(etm_len);
    fread(etm_buf, 1, etm_len, fin);
    fclose(fin);

    // 复现PBKDF2 Master Key
    byte master_key[MASTER_KEY_SIZE];
    pbkdf2_hmac_sha256((const byte *)password, pass_len,
                       salt, SALT_SIZE,
                       iterations, MASTER_KEY_SIZE, master_key);
    
    // HKDF 派生密钥
    byte k_etm_encrypt[AES_KEY_SIZE]; // AES-ETM 加密
    byte k_etm_hmac[HMAC_KEY_SIZE];   // AES-ETM HMAC密钥
    HKDF_SHA256(master_key, MASTER_KEY_SIZE,
                salt, SALT_SIZE,
                (byte *)"enc_key", 7,
                AES_KEY_SIZE,
                k_etm_encrypt);
    HKDF_SHA256(master_key, MASTER_KEY_SIZE,
                salt, SALT_SIZE,
                (byte *)"hmac_key", 8,
                HMAC_KEY_SIZE,
                k_etm_hmac);

    byte *plaintext = (byte *)malloc(etm_len); // 解密后数据不会比加密数据长
    int plaintext_len = decrypt_etm(k_etm_encrypt, k_etm_hmac, etm_buf, etm_len, plaintext);
    free(etm_buf);
    if(plaintext_len < 0){
        printf("Decryption failed\n");
        return -1; // 解密失败
    }
    
    FILE *fout = fopen(output_path, "wb");
    if(fout == NULL){
        free(plaintext);
        return -1; // 文件打开失败
    }
    fwrite(plaintext, 1, plaintext_len, fout);
    fclose(fout);
    free(plaintext);
    return 0;
}