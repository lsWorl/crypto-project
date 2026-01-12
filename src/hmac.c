#include "hmac.h"
#include <string.h>

//HMAC(K,m)=H((K⊕opad) ∥ H((K⊕ipad) ∥ m))
void hmac_sha256(const byte *key, size_t key_len,
                 const byte *message, size_t message_len,
                 byte *out_digest)
{
    byte key_block[HMAC_BLOCK_SIZE];
    byte o_key_pad[HMAC_BLOCK_SIZE];
    byte i_key_pad[HMAC_BLOCK_SIZE];
    byte inner_hash[HMAC_HASH_SIZE];

    // Step 1: 准备密钥块
    if (key_len > HMAC_BLOCK_SIZE) {    //若密钥长度大于块大小，则先进行哈希变成32字节
        sha256(key, key_len, key_block);
        memset(key_block + HMAC_HASH_SIZE, 0, HMAC_BLOCK_SIZE - HMAC_HASH_SIZE);
    } else {
        memcpy(key_block, key, key_len);    //若密钥长度小于等于块大小，则直接复制并填充0
        memset(key_block + key_len, 0, HMAC_BLOCK_SIZE - key_len);
    }

    // Step 2: 计算o_key_pad和i_key_pad
    for (size_t i = 0; i < HMAC_BLOCK_SIZE; i++) {
        o_key_pad[i] = key_block[i] ^ 0x5c; //opad = 0x5c重复填充64字节
        i_key_pad[i] = key_block[i] ^ 0x36; //ipad = 0x36重复填充64字节
    }

    // Step 3: 进行内层哈希
    byte inner_data[HMAC_BLOCK_SIZE + message_len];
    memcpy(inner_data, i_key_pad, HMAC_BLOCK_SIZE);
    memcpy(inner_data + HMAC_BLOCK_SIZE, message, message_len);
    sha256(inner_data, HMAC_BLOCK_SIZE + message_len, inner_hash);

    // Step 4: 进行外层哈希
    byte outer_data[HMAC_BLOCK_SIZE + HMAC_HASH_SIZE];
    memcpy(outer_data, o_key_pad, HMAC_BLOCK_SIZE);
    memcpy(outer_data + HMAC_BLOCK_SIZE, inner_hash, HMAC_HASH_SIZE);
    sha256(outer_data, HMAC_BLOCK_SIZE + HMAC_HASH_SIZE, out_digest);
}