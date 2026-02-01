//自我实现x25519
#include "crypto/x25519_self.h"

static void unpack25519(field_elem out, const byte in[32]) {
    for (int i = 0; i < 16; i++) {
        out[i] = ((int64_t)in[2 * i]) + (((int64_t)in[2 * i + 1]) << 8);
    }
    out[15] &= 0x7FFF; // 清除最高位
}

static void carry25519(field_elem elem) {
    int64_t carry;
    for (int i = 0; i < 16; i++) {
        carry = elem[i] >> 16;
        elem[i] -= carry << 16;
        if (i < 15) {
            elem[i + 1] += carry;   // 传播进位
        } else {
            elem[0] += carry * 38; // 2^255 ≡ 19 (mod p) 进位
        }
    }
}
//有限域加法
static void fadd(field_elem out, const field_elem a, const field_elem b) {
    for (int i = 0; i < 16; i++) {
        out[i] = a[i] + b[i];
    }
}
//有限域减法
static void fsub(field_elem out, const field_elem a, const field_elem b) {
    for (int i = 0; i < 16; i++) {
        out[i] = a[i] - b[i];
    }
}

//有限域乘法
static void fmul(field_elem out, const field_elem a, const field_elem b) {
    int64_t product[31];
    for(int i = 0; i < 31; i++) {
        product[i] = 0;
    }
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 16; j++) {
            product[i + j] += a[i] * b[j];
        }
    }
    for (int i = 0; i < 15; i++) {
        product[i] += 38 * product[i + 16];
    }
    for (int i = 0; i < 16; i++) {
        out[i] = product[i];
    }
    carry25519(out);
    carry25519(out);
}

//有限域求逆
static void finverse(field_elem out, const field_elem in){
    field_elem c;
    for(int i = 0; i <16; i++){
        c[i] = in[i];
    }
    for(int i = 253; i >=0; i--){
        fmul(c, c, c);
        if(i != 2 && i !=4){
            fmul(c, c, in);
        }
    }
    for(int i =0; i <16; i++){
        out[i] = c[i];
    }
}
//条件交换, bit为1时交换,为0时不交换
static void swap25519(field_elem p, field_elem q,int bit){
    int64_t mask = ~(bit -1);
    for(int i =0; i <16; i++){
        int64_t temp = mask & (p[i] ^ q[i]);
        p[i] ^= temp;
        q[i] ^= temp;
    }
}

static void pack25519(byte out[32], const field_elem in) {
    field_elem t;
    for (int i = 0; i < 16; i++) {
        t[i] = in[i];
    }
    carry25519(t);
    carry25519(t);
    carry25519(t);
    for (int i = 0; i < 16; i++) {
        out[2 * i] = t[i] & 0xFF;
        out[2 * i + 1] = (t[i] >> 8) & 0xFF;
    }
}