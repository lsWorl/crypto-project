#include "sha256.h"

// 循环右移n位  对应FIPS180-4的3.2.4
#define ROTRIGHT(word, bits) (((word) >> (bits)) | ((word) << (32 - (bits))))

// 选择函数 对应FIPS180-4的4.1.2
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))

// 多路选择函数 对应FIPS180-4的4.1.2
#define MAJ(x, y, z) ((x) & (y) ^ (x & z) ^ (y & z))

// 大写希格玛函数 对应FIPS180-4的4.1.2 用于工作变量
#define EP0(x) (ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22))
#define EP1(x) (ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25))
// 小写希格玛函数 对应FIPS180-4的4.1.2 用于消息调度
#define SIG0(x) (ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ ((x) >> 10))

const uint32_t sha256_initial_hash[8] = { // 每个值取自前八个素数的立方根小数部分的前32位
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19};

const uint32_t sha256_round_constants[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static void sha256_pad(const byte *input, size_t input_len, byte **padded_msg, size_t *padded_len)
{

    size_t remainder = input_len % SHA256_BLOCK_SIZE;                             // 最后一个块中的字节数
    size_t padding_len = (remainder < 56) ? (56 - remainder) : (120 - remainder); // 需要预留8字节存放原始消息的长度
    *padded_len = input_len + padding_len + 8;                                    // 总长度=原始长度+填充长度+8字节长度信息
    *padded_msg = (byte *)malloc(*padded_len);
    if (*padded_msg == NULL)
    {
        printf("Memory allocation failed\n");
        exit(1);
    }
    memcpy(*padded_msg, input, input_len);                   // 复制原始消息
    (*padded_msg)[input_len] = 0x80;                         // 将0x80添加到填充开始处
    memset(*padded_msg + input_len + 1, 0, padding_len - 1); // 填充0x00

    uint64_t bit_len = input_len * 8;
    // 将最后8字节的长度信息存储为大端格式
    for (int i = 0; i < 8; i++)
    {
        (*padded_msg)[*padded_len - 1 - i] = (byte)((bit_len >> (i * 8)) & 0xFF);
    }
}

static void sha256_compress(const byte *block, uint32_t hash[8])
{
    uint32_t w[64];
    // 消息调度  对应FIPS180-4的6.2.2
    for (int i = 0; i < 16; i++) // 将字节流转换为大端格式的32位字填充到w数组
    {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++)
    {
        w[i] = SIG1(w[i - 2]) + w[i - 7] + SIG0(w[i - 15]) + w[i - 16];
    }
    // 初始化工作变量
    uint32_t a = hash[0];
    uint32_t b = hash[1];
    uint32_t c = hash[2];
    uint32_t d = hash[3];
    uint32_t e = hash[4];
    uint32_t f = hash[5];
    uint32_t g = hash[6];
    uint32_t h = hash[7];
    // 主循环  对应FIPS180-4的6.2.2
    for (int i = 0; i < 64; i++)
    {
        uint32_t T1 = h + EP1(e) + CH(e, f, g) + sha256_round_constants[i] + w[i];
        uint32_t T2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    // 更新哈希值
    hash[0] += a;
    hash[1] += b;
    hash[2] += c;
    hash[3] += d;
    hash[4] += e;
    hash[5] += f;
    hash[6] += g;
    hash[7] += h;
}

void sha256(const byte *input, size_t input_len, byte *digest)
{
    uint32_t hash[8];
    // 初始化哈希值
    for (int i = 0; i < 8; i++)
    {
        hash[i] = sha256_initial_hash[i];
    }

    // 消息填充
    byte *padded_msg = NULL;
    size_t padded_len = 0;
    sha256_pad(input, input_len, &padded_msg, &padded_len);

    for(size_t offset = 0; offset < padded_len; offset += SHA256_BLOCK_SIZE)
    {
        sha256_compress(padded_msg + offset, hash);
    }

}