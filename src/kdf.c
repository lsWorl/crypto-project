#include "crypto/kdf.h"
#include "crypto/hmac.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void pbkdf2_hmac_sha256(const byte *password, size_t password_len,
                        const byte *salt, size_t salt_len,
                        int iterations, size_t dk_len, byte *out_dk)
{
    if (iterations < 1)
    {
        printf("Invalid iterations for PBKDF2\n");
        return;
    }
    if(dk_len < 1)
    {
        printf("Derived key length must be greater than 0\n");
        return;
    }
    if(salt_len < 1)
    {
        printf("Salt length must be greater than 0\n");
        return;
    }

    byte *input = (byte *)malloc(salt_len + 4); // 盐值 + 4字节块索引
    memcpy(input, salt, salt_len);

    byte u[SHA256_HASH_SIZE];   // 记录每次迭代的U值
    byte t[SHA256_HASH_SIZE];   // 记录每个块的最终值T
    size_t blocks = (dk_len + SHA256_HASH_SIZE - 1) / SHA256_HASH_SIZE; // 需要生成的块数，向上取整

    // 计算每个子密钥块Ti
    for(size_t i = 1; i <= blocks; i++)  // 块索引从1开始,避免块编号0与空盐冲突
    {
        // 设置块索引（大端格式）
        input[salt_len]     = (byte)((i >> 24) & 0xFF);
        input[salt_len + 1] = (byte)((i >> 16) & 0xFF);
        input[salt_len + 2] = (byte)((i >> 8) & 0xFF);
        input[salt_len + 3] = (byte)(i & 0xFF);

        // U1 = HMAC_SHA256(P, S || INT(i))
        hmac_sha256(password, password_len, input, salt_len + 4, u);
        memcpy(t, u, SHA256_HASH_SIZE);

        // U2 到 Uc
        for(int j = 1; j < iterations; j++)
        {
            hmac_sha256(password, password_len, u, SHA256_HASH_SIZE, u);
            for(int k = 0; k < SHA256_HASH_SIZE; k++)
            {
                t[k] ^= u[k]; // T_i = U1 ^ U2 ^ ... ^ Uc
            }
        }

        // 将T_i复制到输出密钥中
        size_t offset = (i - 1) * SHA256_HASH_SIZE; // offset为块在输出密钥中的起始位置
        size_t to_copy = (dk_len - offset) < SHA256_HASH_SIZE ? (dk_len - offset) : SHA256_HASH_SIZE;
        memcpy(out_dk + offset, t, to_copy);
    }
    free(input);
}

static int hkdf_extract(const byte *salt, size_t salt_len,
                 const byte *ikm, size_t ikm_len,
                 byte *prk)
{
    if(ikm == NULL || ikm_len == 0 || prk == NULL)
    {
        return -1; // 参数无效
    }
    // 如果没有提供盐值，使用全零盐值
    byte zero_salt[HKDF_HASH_SIZE];
    if (salt == NULL || salt_len == 0)
    {
        memset(zero_salt, 0, HKDF_HASH_SIZE);
        salt = zero_salt;
        salt_len = HKDF_HASH_SIZE;
    }
    // PRK = HMAC_SHA256(salt, IKM)
    hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
    return 0;
}

static int hkdf_expand(const byte *prk, size_t prk_len,
                const byte *info, size_t info_len,
                size_t okm_len, byte *okm)
{
    if(prk == NULL || prk_len != HKDF_HASH_SIZE || okm == NULL || okm_len == 0)
    {
        return -1; // 参数无效
    }

    size_t n = (okm_len + HKDF_HASH_SIZE - 1) / HKDF_HASH_SIZE; // 需要生成的块数
    if(n > 255)
    {
        return -1; // 输出密钥长度过长
    }

    byte t[HKDF_HASH_SIZE];
    byte block_input[HKDF_HASH_SIZE + info_len + 1]; // T(i-1) || info || i ,加一字节用于块索引
    size_t offset = 0;

    for(size_t i = 1; i <= n; i++)  // 块索引从1开始，避免块编号0与空信息冲突
    {
        size_t input_len = 0;
        if(i > 1)
        {
            memcpy(block_input, t, HKDF_HASH_SIZE);  // 追加上一个块T(i-1)
            input_len += HKDF_HASH_SIZE;            // 更新输入长度
        }
        if(info != NULL && info_len > 0)
        {
            memcpy(block_input + input_len, info, info_len);  // 追加info
            input_len += info_len;
        }
        block_input[input_len] = (byte)i; // 块索引i
        input_len += 1;

        hmac_sha256(prk, prk_len, block_input, input_len, t);

        size_t to_copy = (okm_len - offset) < HKDF_HASH_SIZE ? (okm_len - offset) : HKDF_HASH_SIZE;
        memcpy(okm + offset, t, to_copy);
        offset += to_copy;
    }
    return 0;
}

void HKDF_SHA256(const byte *ikm, size_t ikm_len,
                   const byte *salt, size_t salt_len,
                   const byte *info, size_t info_len,
                   size_t okm_len, byte *out_okm)
{
    byte prk[HKDF_HASH_SIZE];
    if(hkdf_extract(salt, salt_len, ikm, ikm_len, prk) != 0)
    {
        printf("HKDF extract failed\n");
        return;
    }
    if(hkdf_expand(prk, HKDF_HASH_SIZE, info, info_len, okm_len, out_okm) != 0)
    {
        printf("HKDF expand failed\n");
        return;
    }
}