#include "AESEncryption.h"

// 字节替代操作
void SubBytes(void)
{
    int i, j;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            state[i][j] = Sbox[state[i][j]];
        }
    }
}

// 行移位操作
void shift_rows(void)
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
            state[i][j] = temp[i][(j + i) % 4];
        }
    }
}

// 列混合
void MixColumns(void)
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
        state[0][i] = xtime(temp[0][i]) ^ mul_by_03(temp[1][i]) ^ temp[2][i] ^ temp[3][i];
        state[1][i] = temp[0][i] ^ xtime(temp[1][i]) ^ mul_by_03(temp[2][i]) ^ temp[3][i];
        state[2][i] = temp[0][i] ^ temp[1][i] ^ xtime(temp[2][i]) ^ mul_by_03(temp[3][i]);
        state[3][i] = mul_by_03(temp[0][i]) ^ temp[1][i] ^ temp[2][i] ^ xtime(temp[3][i]);
    }
}

// AES加密函数
void encrypt(byte key[16], byte input[16], byte output[16]) {
    byte roundKeys[44][4];
    int round;
    
    init_state(input);
    key_expansion(key, roundKeys);
    add_round_key(roundKeys, 0);
    
    for(round = 1; round < Nr; round++) {
        SubBytes();
        shift_rows();
        MixColumns();
        add_round_key(roundKeys, round);
    }
    
    SubBytes();
    shift_rows();
    add_round_key(roundKeys, Nr);
    
    int c, r;
    for(c = 0; c < 4; c++) {
        for(r = 0; r < 4; r++) {
            output[r + 4 * c] = state[r][c];
        }
    }
}




// 使用CBC模式的AES加密函数
void encrypt_cbc(byte key[16], byte iv[16], byte *input, byte *output, int length) {
    size_t block_count = length / BLOCK_SIZE;
    byte previous_block[BLOCK_SIZE];
    memcpy(previous_block, iv, BLOCK_SIZE); // 初始化前一个块为IV
    for (size_t i = 0; i < block_count; i++) {
        byte block[BLOCK_SIZE];
        // XOR当前块与前一个加密块（或IV）
        for (size_t j = 0; j < BLOCK_SIZE; j++) {
            block[j] = input[i * BLOCK_SIZE + j] ^ previous_block[j];
        }
        byte encrypted_block[BLOCK_SIZE];
        encrypt(key, block, encrypted_block);
        memcpy(&output[i * BLOCK_SIZE], encrypted_block, BLOCK_SIZE);
        memcpy(previous_block, encrypted_block, BLOCK_SIZE); // 更新前一个块
    }
}

//EtM模式加密   输出IV||Ciphertext||TAG
int encrypt_etm(byte Ciperkey[16],byte Mackey[32], byte *input, size_t input_len, byte *output) {
    if (input_len < 0) return -1;
    if(Ciperkey == NULL || Mackey == NULL || input == NULL || output == NULL) return -1;

    // 生成随机IV
    byte iv[ETM_IV_SIZE];
    generate_random_iv(iv);
    memcpy(output, iv, ETM_IV_SIZE); // 将IV写入输出

    // PKCS#7填充
    int padded_len;
    byte *padded_input = (byte *)malloc(input_len + BLOCK_SIZE);
    if(padded_input == NULL) {
        printf("Memory allocation failed\n");
        return -1;
    }
    pkcs7_pad(input, input_len, padded_input, &padded_len);

    // 加密数据
    byte *encrypted_data = (byte *)malloc(padded_len);
    if(encrypted_data == NULL) {
        printf("Memory allocation failed\n");
        free(padded_input);
        return -1;
    }
    encrypt_cbc(Ciperkey, iv, padded_input, encrypted_data, padded_len);
    memcpy(output + ETM_IV_SIZE, encrypted_data, padded_len);

    // 计算HMAC
    byte hmac[ETM_HMAC_SIZE];
    hmac_sha256(Mackey, 32, output, ETM_IV_SIZE + padded_len, hmac);
    memcpy(output + ETM_IV_SIZE + padded_len, hmac, ETM_HMAC_SIZE);

    // 清理
    free(padded_input);
    free(encrypted_data);

    return ETM_OVERHEAD + padded_len; // 返回总输出长度
}


// 对文件进行加密
void encrypt_file(const char *input_filename, const char *output_filename, byte key[16]) {
    FILE *input_file = fopen(input_filename, "rb");
    FILE *output_file = fopen(output_filename, "wb");
    if (!input_file || !output_file) {
        printf("Error opening files.\n");
        return;
    }

    // 生成随机IV并写入输出文件
    byte iv[16];
    generate_random_iv(iv);
    fwrite(iv, 1, 16, output_file);

    // 读取输入文件内容
    fseek(input_file, 0, SEEK_END);
    long input_length = ftell(input_file);  // 通过文件指针获取文件长度
    fseek(input_file, 0, SEEK_SET);  // 回到文件开头
    byte *input_data = (byte *)malloc(input_length);
    fread(input_data, 1, input_length, input_file);

    // 进行PKCS#7填充
    int padded_length;
    byte *padded_data = (byte *)malloc(input_length + BLOCK_SIZE); // 最多多一个块的空间
    pkcs7_pad(input_data, input_length, padded_data, &padded_length);

    // 加密数据
    byte *encrypted_data = (byte *)malloc(padded_length);
    encrypt_cbc(key, iv, padded_data, encrypted_data, padded_length);

    // 写入加密数据到输出文件
    fwrite(encrypted_data, 1, padded_length, output_file);

    // 清理
    free(input_data);
    free(padded_data);
    free(encrypted_data);
    fclose(input_file);
    fclose(output_file);
}