#include "AESDecryption.h"

//使用逆S盒对状态矩阵进行字节替代
void inv_sub_bytes(byte state[4][4])
{
    int i, j;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            state[i][j] = InvSBox[state[i][j]];
        }
    }
}



// 逆行移位操作，即将每一行向右循环移位
void inv_shift_rows(byte state[4][4])
{
    byte temp[4][4];
    int i, j;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            temp[i][j] = state[i][j];
        }
    }
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            state[i][j] = temp[i][(j - i + 4) % 4];
        }
    }
}


// 逆列混合操作
void inv_mix_columns(byte state[4][4])
{
    byte temp[4][4];
    int i, j;

    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            temp[i][j] = state[i][j];
        }
    }

    for (j = 0; j < 4; j++)
    {
        state[0][j] = (byte)(mul_by_0e(temp[0][j]) ^ mul_by_0b(temp[1][j]) ^ mul_by_0d(temp[2][j]) ^ mul_by_09(temp[3][j]));
        state[1][j] = (byte)(mul_by_09(temp[0][j]) ^ mul_by_0e(temp[1][j]) ^ mul_by_0b(temp[2][j]) ^ mul_by_0d(temp[3][j]));
        state[2][j] = (byte)(mul_by_0d(temp[0][j]) ^ mul_by_09(temp[1][j]) ^ mul_by_0e(temp[2][j]) ^ mul_by_0b(temp[3][j]));
        state[3][j] = (byte)(mul_by_0b(temp[0][j]) ^ mul_by_0d(temp[1][j]) ^ mul_by_09(temp[2][j]) ^ mul_by_0e(temp[3][j]));
    }
}

//解密函数
void decrypt(byte key[16], byte input[16], byte output[16])
{
    byte roundKeys[44][4];
    int round;

    // 使用全局状态矩阵并初始化（common.c 中的 state）
    init_state(input);

    // 密钥扩展
    key_expansion(key, roundKeys);

    // 初始轮密钥加
    add_round_key(roundKeys, Nr);

    // 主轮
    for (round = Nr - 1; round >= 1; round--)
    {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(roundKeys, round);
        inv_mix_columns(state);
    }

    // 最终轮
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(roundKeys, 0);

    // 输出结果（从全局 state 读取）
    for (int c = 0; c < 4; c++)
    {
        for (int r = 0; r < 4; r++)
        {
            output[r + 4 * c] = state[r][c];
        }
    }
}

// 使用CBC模式的AES解密函数
void decrypt_cbc(byte key[16], byte iv[16], byte *input, byte *output, int length)
{
    size_t block_count = length / BLOCK_SIZE;
    byte previous_block[BLOCK_SIZE];
    memcpy(previous_block, iv, BLOCK_SIZE); // 初始化前一个块为IV
    for(size_t i = 0; i < block_count; i++)
    {
        byte block[BLOCK_SIZE];
        memcpy(block, input + i * BLOCK_SIZE, BLOCK_SIZE);

        byte decrypted_block[BLOCK_SIZE];
        decrypt(key, block, decrypted_block);

        // 与前一个密文块（或IV）进行异或操作
        for (int j = 0; j < BLOCK_SIZE; j++)
        {
            output[i * BLOCK_SIZE + j] = decrypted_block[j] ^ previous_block[j];
        }

        // 更新前一个块为当前密文块
        memcpy(previous_block, block, BLOCK_SIZE);
    }
}

//对文件进行AES解密
void decrypt_file(const char *input_filename, const char *output_filename, byte key[16])
{
    FILE *fin = fopen(input_filename, "rb");
    FILE *fout = fopen(output_filename, "wb");
    if (!fin || !fout)
    {
        printf("File open error!\n");
        if (fin) fclose(fin);
        if (fout) fclose(fout);
        return;
    }

    // 读取IV
    byte iv[BLOCK_SIZE];
    fread(iv, 1, BLOCK_SIZE, fin);

    // 获取文件大小
    fseek(fin, 0, SEEK_END);
    long file_size = ftell(fin) - BLOCK_SIZE; // 减去IV的大小
    fseek(fin, BLOCK_SIZE, SEEK_SET);         // 跳过IV

    // 读取加密数据
    byte *ciphertext = (byte *)malloc(file_size);
    fread(ciphertext, 1, file_size, fin);

    // 解密数据缓冲区
    byte *plaintext = (byte *)malloc(file_size);

    // 执行CBC解密
    decrypt_cbc(key, iv, ciphertext, plaintext, file_size);

    // 移除填充
    byte *unpadded_plaintext = (byte *)malloc(file_size);
    int unpadded_len = pkcs7_unpad(plaintext, file_size, unpadded_plaintext);
    if (unpadded_len < 0)
    {
        printf("Invalid padding!\n");
        free(ciphertext);
        free(plaintext);
        free(unpadded_plaintext);
        fclose(fin);
        fclose(fout);
        return;
    }

    // 写入解密后的数据
    fwrite(unpadded_plaintext, 1, unpadded_len, fout);

    // 清理资源
    free(ciphertext);
    free(plaintext);
    free(unpadded_plaintext);
    fclose(fin);
    fclose(fout);
}