#include "crypto/gcm.h"
#include <string.h>

// GHASH乘法实现    参考NIST SP 800-38D 6.3
// 使用标准的“按位乘法 + 左移”实现（与 NIST 伪代码一致）。
static void gcm_mult(const byte *X, const byte *Y, byte *Z)
{
    byte V[16];
    byte Zt[16] = {0};

    memcpy(V, Y, 16);

    for (int i = 0; i < 128; i++) {
        int xi = (X[i/8] >> (7 - (i%8))) & 1;

        if (xi) {
            for (int j = 0; j < 16; j++)
                Zt[j] ^= V[j];
        }

        int lsb = V[15] & 1;

        for (int j = 15; j > 0; j--)
            V[j] = (V[j] >> 1) | (V[j-1] << 7);

        V[0] >>= 1;

        if (lsb)
            V[0] ^= 0xe1;
    }

    memcpy(Z, Zt, 16);
}

// GHASH函数     参考NIST SP 800-38D 6.4
// Y is an in/out value (initial state), allowing incremental hashing of A||C||len
static void ghash(const byte *H, const byte *X, size_t len, byte *Y)
{
    byte Xi[16];
    // NOTE: Y is treated as the current GHASH state (not re?initialized here).
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
    encrypt((byte *)key, H, H); // H = E(K, 0^128)

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
    gctr(key, J0, plaintext, pt_len, ciphertext); // C = GCTR(K, J0, P)

    // GHASH(A || C || len)
    byte len_block[16];
    uint64_t a_bits = aad_len * 8, c_bits = pt_len * 8;
    for (int i = 0; i < 8; i++)
    {
        len_block[i] = (a_bits >> (56 - i * 8)) & 0xFF;
        len_block[8 + i] = (c_bits >> (56 - i * 8)) & 0xFF;
    }

    // S = GHASH(H, A || C || len)
    memset(S, 0, 16);
    if (aad_len > 0)
        ghash(H, aad, aad_len, S);
    if (pt_len > 0)
        ghash(H, ciphertext, pt_len, S);
    ghash(H, len_block, 16, S);

    // T = MSB_128( E(K, J0) ⊕ S )  (E(K, J0), not GCTR)
    byte E_J0[16];
    encrypt((byte *)key, J0, E_J0);
    for (int i = 0; i < 16; i++)
        tag[i] = E_J0[i] ^ S[i];

    return 0;
}

// 解密函数 对应算法5
int aes_gcm_decrypt(const byte *key, const byte *iv, size_t iv_len, const byte *ciphertext, size_t ct_len,
                    const byte *aad, size_t aad_len, byte *plaintext, byte *tag)
{
    // ct_len is plaintext length; it can be zero.
    byte H[16] = {0}, J0[16] = {0}, len_block[16], S[16] = {0};
    // step 2
    encrypt((byte *)key, H, H);
    // step 3
    if (iv_len == 12) {
        memcpy(J0, iv, 12);
        J0[15] = 1;
    } else {
        return -1;
    }
    // step 4
    gctr(key, J0, ciphertext, ct_len, plaintext);

    uint64_t a_bits = (uint64_t)aad_len * 8;
    uint64_t c_bits = (uint64_t)ct_len * 8;
    for (int i = 0; i < 8; i++) {
        len_block[i]   = (a_bits >> (56 - i*8)) & 0xFF;
        len_block[8+i] = (c_bits >> (56 - i*8)) & 0xFF;
    }

    // S = GHASH(H, A || C || len)
    memset(S, 0, 16);
    if (aad_len > 0)
        ghash(H, aad, aad_len, S);
    if (ct_len > 0)
        ghash(H, ciphertext, ct_len, S);
    ghash(H, len_block, 16, S);

    byte expected_tag[16];
    byte E_J0[16];
    encrypt((byte *)key, J0, E_J0);
    for (int i = 0; i < 16; i++)
        expected_tag[i] = E_J0[i] ^ S[i];

    // 常量时间比较（防时序攻击，使用你项目里的 ct_equal）
    if (!ct_equal(tag, expected_tag, GCM_TAG_SIZE)) {
        memset(plaintext, 0, ct_len);   // 安全擦除，防止泄露
        return -1;  // CRYPTO_ERR_MAC
    }
    return (int)ct_len;  // 成功返回明文长度
}