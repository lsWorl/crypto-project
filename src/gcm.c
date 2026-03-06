#include "crypto/gcm.h"
#include <string.h>

// GHASH乘法实现    参考NIST SP 800-38D 6.3
static void gcm_multi(const byte *x, const byte *y, byte *z)
{ // z作为乘法结果
    byte V[16], Z[16] = {0};
    // step 2  step1是将被乘序列放入x中
    memcpy(V, y, 16); // 将V0置为Y
    // step 3
    for (int i = 0; i < 128; i++)
    {
        byte xi = (x[i >> 3] >> (7 - (i & 7))) & 1; // 获取所在字节的最高位（高位优先）
        if (xi)
        { // bit为1时
            for (int j = 0; j < 16; j++)
                Z[j] ^= V[j];
        }
        byte lsb = V[15] & 1; // 获取V中最低位
        // right shift
        for (int j = 15; j > 0; j--)
        {
            V[j] = (V[j] >> 1) | (V[j - 1] << 7);
        }
        V[0] >>= 1;
        if (lsb)
        {
            V[0] ^= 0xe1; // 对应不可约多项式R=1110 0001
        }
    }
    memcpy(z, Z, 16); // 返回结果
}

// GHASH函数     参考NIST SP 800-38D 6.4
static void ghash(const byte *H, const byte *X, size_t len, byte *Y)
{
    byte Xi[16];
    memset(Y, 0, 16);
    for (size_t i = 0; i < len; i += 16) // 对块进行处理
    {
        size_t block_len = (len - i < 16) ? (len - i) : 16;
        memset(Xi, 0, 16);
        memcpy(Xi, X + i, block_len);
        for (int j = 0; j < 16; j++)
            Y[j] ^= Xi[j];
        gcm_mult(Y, H, Y);
    }
}

// inc_32函数 最后 4 字节（32 位）按大端序执行无符号整数加 1 操作
static void inc_32(byte *counter)
{
    uint32_t n = ((uint32_t)counter[12] << 24) |
                 ((uint32_t)counter[13] << 16) |
                 ((uint32_t)counter[14] << 8) | counter[15];
    n++;
    counter[12] = (n >> 24) & 0xFF;
    counter[13] = (n >> 16) & 0xFF;
    counter[14] = (n >> 8) & 0xFF;
    counter[15] = n & 0xFF;
}

// gctr函数     参考NIST SP 800-38D 6.5
static void gctr(const byte *key, byte *ICB, const byte *in, size_t len, byte *out)
{
    byte counter[16], keystream[16];
    memcpy(counter, ICB, 16); // 将计数器复制到counter中
    size_t i = 0;
    while (i < len)
    {
        inc_32(counter);                          // 等同于step 5
        encrypt((byte *)key, counter, keystream); // 调用AES
        size_t block = (len - i < 16) ? (len - i) : 16;
        for (size_t j = 0; j < block; j++)
        {
            out[i + j] = in[i + j] ^ keystream[j]; // 等同于step 6之后的步骤
        }
        i += block;
    }
}

// 主加密函数    参考NIST SP 800-38D 7
int aes_gcm_encrypt(const byte *key, const byte *iv, size_t iv_len,
                    const byte *plaintext, size_t pt_len,
                    const byte *aad, size_t aad_len,
                    byte *ciphertext, byte *tag)
{
    // step 1
    byte H[16] = {0}, J0[16] = {0}, S[16] = {0};
    encrypt((byte *)key, H, H); // H = E(K, 0???)

    // J0 计算（NIST 7.1）  判断长度是否为96bit (为简化起见，先固定传IV向量为96bit) step 2
    if (iv_len == 12)
    {
        memcpy(J0, iv, 12);
        J0[15] = 1;
    }
    else
    {
        // 任意长度 IV
        ghash(H, iv, iv_len, J0);
        // 后面再补长度编码...
    }

    // 加密  step 3
    gctr(key, J0, plaintext, pt_len, ciphertext);

    // GHASH(A || C || len)
    byte len_block[16];
    // step 4
    uint64_t a_bits = aad_len * 8, c_bits = pt_len * 8;
    for (int i = 0; i < 8; i++)
    {
        len_block[i] = (a_bits >> (56 - i * 8)) & 0xFF;
        len_block[8 + i] = (c_bits >> (56 - i * 8)) & 0xFF;
    }
    ghash(H, aad, aad_len, S);
    byte temp[16];
    ghash(H, ciphertext, pt_len, temp);
    for (int i = 0; i < 16; i++)
        S[i] ^= temp[i];
    ghash(H, len_block, 16, temp);
    for (int i = 0; i < 16; i++)
        S[i] ^= temp[i];

    // T = MSB_128( E(K, J0) ⊕ S )
    byte T[16];
    gctr(key, J0, S, 16, T); // GCTR 一个块
    memcpy(tag, T, GCM_TAG_SIZE);

    return 0;
}