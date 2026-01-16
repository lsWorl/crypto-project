#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "crypto/crypto_types.h"



// 外部变量声明
extern byte state[4][4];  //状态矩阵

// S盒常量声明
extern const byte Sbox[256];

// 轮常量声明
extern const byte Rcon[11];

// 逆S盒常量声明
extern const byte InvSBox[256];

// 函数声明
void init_state(byte input[STATE_SIZE]);
byte xtime(byte x);
byte mul_by_03(byte x);
void key_expansion(byte key[STATE_SIZE], byte roundKeys[44][4]);
void add_round_key(byte roundKeys[44][4], int round);
void print_state(void);
byte mul_by_09(byte x);
byte mul_by_0b(byte x);
byte mul_by_0d(byte x);
byte mul_by_0e(byte x);
void pkcs7_pad(byte *input, int input_len, byte *output, int *output_len);
int pkcs7_unpad(byte *input, int input_len, byte *output);
void generate_random_iv(byte iv[16]);

// 常量时间比较函数，用于HMAC验证
int ct_equal(const byte *a, const byte *b, size_t len);


#endif // COMMON_H