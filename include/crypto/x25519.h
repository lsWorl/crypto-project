/*
 * X25519 椭圆曲线 Diffie-Hellman 密钥交换模块
 * =============================================
 * 
 * 本模块封装了 X25519 (Curve25519) ECDH 密钥交换功能
 * 底层使用 libsodium 实现，提供简洁统一的接口
 * 
 * 功能特性：
 * - 密钥对生成（公钥/私钥）
 * - 基础密钥交换（计算共享密钥）
 * - 会话密钥派生（双向独立密钥）
 * - 内存安全清除
 * 
 * 适用场景：
 * - TLS/DTLS 握手
 * - 端到端加密通信
 * - 安全信道建立
 * - 密钥协商协议
 */

#ifndef X25519_H
#define X25519_H

#include "crypto_types.h"
#include <stdint.h>

/*
 * ============================================================================
 * 常量定义
 * ============================================================================
 */

// X25519 密钥尺寸（已在 crypto_types.h 中定义，这里重新声明便于理解）
// #define X25519_KEY_SIZE 32  // 32 字节 = 256 位

// 会话密钥尺寸
#define X25519_SESSION_KEY_SIZE 32  // 派生的会话密钥大小

/*
 * ============================================================================
 * 错误码定义
 * ============================================================================
 */

typedef enum {
    X25519_SUCCESS = 0,           // 操作成功
    X25519_ERROR_INVALID_PARAM,   // 参数无效（空指针等）
    X25519_ERROR_KEY_EXCHANGE,    // 密钥交换失败
    X25519_ERROR_INIT,            // 初始化失败
    X25519_ERROR_KEYPAIR_GEN      // 密钥对生成失败
} x25519_error_t;

/*
 * ============================================================================
 * 核心接口函数
 * ============================================================================
 */

/**
 * 初始化 X25519 模块
 * 
 * 必须在使用任何其他 X25519 函数之前调用一次
 * 内部会初始化 libsodium 库
 * 
 * @return X25519_SUCCESS 成功
 *         X25519_ERROR_INIT 初始化失败
 * 
 * 示例：
 *   if (x25519_init() != X25519_SUCCESS) {
 *       fprintf(stderr, "X25519 初始化失败\n");
 *       return -1;
 *   }
 */
x25519_error_t x25519_init(void);

/**
 * 生成 X25519 密钥对
 * 
 * 生成一个随机的公钥/私钥对，用于密钥交换
 * 私钥必须保密，公钥可以公开传输
 * 
 * @param public_key  [out] 输出的公钥（32字节）
 * @param secret_key  [out] 输出的私钥（32字节）
 * 
 * @return X25519_SUCCESS 成功
 *         X25519_ERROR_INVALID_PARAM 参数为空
 *         X25519_ERROR_KEYPAIR_GEN 生成失败
 * 
 * 示例：
 *   uint8_t public_key[X25519_KEY_SIZE];
 *   uint8_t secret_key[X25519_KEY_SIZE];
 *   
 *   if (x25519_keypair(public_key, secret_key) != X25519_SUCCESS) {
 *       fprintf(stderr, "密钥对生成失败\n");
 *       return -1;
 *   }
 */
x25519_error_t x25519_keypair(uint8_t public_key[X25519_KEY_SIZE],
                              uint8_t secret_key[X25519_KEY_SIZE]);

/**
 * 从私钥计算公钥
 * 
 * 用于从已有的私钥恢复公钥
 * 
 * @param public_key  [out] 输出的公钥（32字节）
 * @param secret_key  [in]  输入的私钥（32字节）
 * 
 * @return X25519_SUCCESS 成功
 *         X25519_ERROR_INVALID_PARAM 参数为空
 * 
 * 示例：
 *   uint8_t public_key[X25519_KEY_SIZE];
 *   uint8_t secret_key[X25519_KEY_SIZE] = { ... }; // 已有的私钥
 *   
 *   x25519_public_key(public_key, secret_key);
 */
x25519_error_t x25519_public_key(uint8_t public_key[X25519_KEY_SIZE],
                                 const uint8_t secret_key[X25519_KEY_SIZE]);

/**
 * X25519 密钥交换（计算共享密钥）
 * 
 * 使用自己的私钥和对方的公钥计算共享密钥
 * Alice 和 Bob 使用各自的私钥和对方的公钥计算，将得到相同的共享密钥
 * 
 * 数学原理：
 *   Alice: shared = alice_secret * bob_public
 *   Bob:   shared = bob_secret * alice_public
 *   结果：alice_secret * bob_public = bob_secret * alice_public
 * 
 * 注意：这个函数返回的是原始的共享密钥，通常不应直接用于加密
 *      应该使用密钥派生函数（KDF）进一步处理
 * 
 * @param shared_key       [out] 输出的共享密钥（32字节）
 * @param my_secret_key    [in]  自己的私钥（32字节）
 * @param their_public_key [in]  对方的公钥（32字节）
 * 
 * @return X25519_SUCCESS 成功
 *         X25519_ERROR_INVALID_PARAM 参数为空
 *         X25519_ERROR_KEY_EXCHANGE 密钥交换失败（可能因为公钥无效）
 * 
 * 示例：
 *   uint8_t shared_key[X25519_KEY_SIZE];
 *   
 *   if (x25519_exchange(shared_key, my_secret, peer_public) != X25519_SUCCESS) {
 *       fprintf(stderr, "密钥交换失败\n");
 *       return -1;
 *   }
 */
x25519_error_t x25519_exchange(uint8_t shared_key[X25519_KEY_SIZE],
                               const uint8_t my_secret_key[X25519_KEY_SIZE],
                               const uint8_t their_public_key[X25519_KEY_SIZE]);

/**
 * 计算客户端会话密钥（带密钥派生）
 * 
 * 高层 API，自动进行密钥派生，生成两个独立的会话密钥
 * 适用于客户端角色，与服务端的密钥派生结果对应
 * 
 * 生成的密钥：
 *   rx_key: 接收密钥（用于解密从服务端接收的数据）
 *   tx_key: 发送密钥（用于加密发送给服务端的数据）
 * 
 * 特性：
 *   - rx_key 和 tx_key 是独立的，提供双向安全
 *   - 防止密钥重用攻击
 *   - 客户端的 tx_key == 服务端的 rx_key
 *   - 客户端的 rx_key == 服务端的 tx_key
 * 
 * @param rx_key           [out] 接收密钥（32字节）
 * @param tx_key           [out] 发送密钥（32字节）
 * @param client_public    [in]  客户端公钥（32字节）
 * @param client_secret    [in]  客户端私钥（32字节）
 * @param server_public    [in]  服务端公钥（32字节）
 * 
 * @return X25519_SUCCESS 成功
 *         X25519_ERROR_INVALID_PARAM 参数为空
 *         X25519_ERROR_KEY_EXCHANGE 密钥交换失败
 * 
 * 示例：
 *   uint8_t rx_key[X25519_SESSION_KEY_SIZE];
 *   uint8_t tx_key[X25519_SESSION_KEY_SIZE];
 *   
 *   if (x25519_client_session_keys(rx_key, tx_key,
 *                                   my_public, my_secret, 
 *                                   server_public) != X25519_SUCCESS) {
 *       fprintf(stderr, "会话密钥派生失败\n");
 *       return -1;
 *   }
 *   
 *   // 使用 tx_key 加密发送，rx_key 解密接收
 */
x25519_error_t x25519_client_session_keys(
    uint8_t rx_key[X25519_SESSION_KEY_SIZE],
    uint8_t tx_key[X25519_SESSION_KEY_SIZE],
    const uint8_t client_public[X25519_KEY_SIZE],
    const uint8_t client_secret[X25519_KEY_SIZE],
    const uint8_t server_public[X25519_KEY_SIZE]);

/**
 * 计算服务端会话密钥（带密钥派生）
 * 
 * 高层 API，自动进行密钥派生，生成两个独立的会话密钥
 * 适用于服务端角色，与客户端的密钥派生结果对应
 * 
 * @param rx_key           [out] 接收密钥（32字节）
 * @param tx_key           [out] 发送密钥（32字节）
 * @param server_public    [in]  服务端公钥（32字节）
 * @param server_secret    [in]  服务端私钥（32字节）
 * @param client_public    [in]  客户端公钥（32字节）
 * 
 * @return X25519_SUCCESS 成功
 *         X25519_ERROR_INVALID_PARAM 参数为空
 *         X25519_ERROR_KEY_EXCHANGE 密钥交换失败
 * 
 * 示例：
 *   uint8_t rx_key[X25519_SESSION_KEY_SIZE];
 *   uint8_t tx_key[X25519_SESSION_KEY_SIZE];
 *   
 *   if (x25519_server_session_keys(rx_key, tx_key,
 *                                   my_public, my_secret,
 *                                   client_public) != X25519_SUCCESS) {
 *       fprintf(stderr, "会话密钥派生失败\n");
 *       return -1;
 *   }
 */
x25519_error_t x25519_server_session_keys(
    uint8_t rx_key[X25519_SESSION_KEY_SIZE],
    uint8_t tx_key[X25519_SESSION_KEY_SIZE],
    const uint8_t server_public[X25519_KEY_SIZE],
    const uint8_t server_secret[X25519_KEY_SIZE],
    const uint8_t client_public[X25519_KEY_SIZE]);

/**
 * 安全清除密钥数据
 * 
 * 使用安全的方式将密钥内存清零，防止被编译器优化掉
 * 在不再需要密钥时应立即调用此函数
 * 
 * @param key  要清除的密钥数据
 * @param len  密钥长度
 * 
 * 示例：
 *   uint8_t secret_key[X25519_KEY_SIZE];
 *   // ... 使用密钥 ...
 *   x25519_clear_key(secret_key, sizeof(secret_key));
 */
void x25519_clear_key(void *key, size_t len);

/*
 * ============================================================================
 * 辅助函数（可选）
 * ============================================================================
 */

/**
 * 获取错误信息字符串
 * 
 * @param error 错误码
 * @return 错误描述字符串
 */
const char* x25519_error_string(x25519_error_t error);

#endif // X25519_H