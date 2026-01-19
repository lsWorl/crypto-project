/*
 * X25519 椭圆曲线 Diffie-Hellman 密钥交换实现
 * 
 * 本文件实现了 X25519 模块的所有接口函数
 * 底层调用 libsodium 库的 crypto_scalarmult_curve25519 和 crypto_kx 系列函数
 */

#include "crypto/x25519.h"
#include "crypto/kdf.h"
#include "sodium.h"
#include <string.h>


//初始化函数
x25519_error_t x25519_init(void) {
    // 初始化 libsodium
    // 返回值：0 = 成功，1 = 已初始化，-1 = 失败
    if (sodium_init() < 0) {
        return X25519_ERROR_INIT;
    }
    return X25519_SUCCESS;
}


//密钥对生成
x25519_error_t x25519_keypair(uint8_t public_key[X25519_KEY_SIZE],
                              uint8_t secret_key[X25519_KEY_SIZE]) {
    // 参数验证
    if (public_key == NULL || secret_key == NULL) {
        return X25519_ERROR_INVALID_PARAM;
    }
    
    // 调用 libsodium 的密钥对生成函数
    // crypto_kx_keypair 内部会：
    //   1. 生成随机私钥
    //   2. 从私钥计算公钥
    if (crypto_kx_keypair(public_key, secret_key) != 0) {
        return X25519_ERROR_KEYPAIR_GEN;
    }
    
    return X25519_SUCCESS;
}

//从私钥计算公钥
x25519_error_t x25519_public_key(uint8_t public_key[X25519_KEY_SIZE],
                                 const uint8_t secret_key[X25519_KEY_SIZE]) {
    // 参数验证
    if (public_key == NULL || secret_key == NULL) {
        return X25519_ERROR_INVALID_PARAM;
    }
    
    // 从私钥计算公钥：public = secret * G（G 是基点）
    // crypto_scalarmult_base 执行标量乘法
    if (crypto_scalarmult_curve25519_base(public_key, secret_key) != 0) {
        return X25519_ERROR_KEYPAIR_GEN;
    }
    
    return X25519_SUCCESS;
}


//X25519 密钥交换
x25519_error_t x25519_exchange(uint8_t shared_key[X25519_KEY_SIZE],
                               const uint8_t my_secret_key[X25519_KEY_SIZE],
                               const uint8_t their_public_key[X25519_KEY_SIZE]) {
    // 参数验证
    if (shared_key == NULL || my_secret_key == NULL || their_public_key == NULL) {
        return X25519_ERROR_INVALID_PARAM;
    }
    
    // 执行 X25519 密钥交换
    // shared = my_secret * their_public
    
    // 数学原理： 在X25519中，公钥是通过将私钥与基点G相乘得到的点。其中G为Curve25519的固定基点
    //   Alice: shared = a * (b*G) = (a*b)*G        
    //   Bob:   shared = b * (a*G) = (b*a)*G
    //   因为标量乘法满足交换律和结合律，所以 (a*b)*G = (b*a)*G

    // crypto_scalarmult 返回 -1 表示失败（通常是因为 their_public_key 无效）
    if (crypto_scalarmult_curve25519(shared_key, my_secret_key, their_public_key) != 0) {
        return X25519_ERROR_KEY_EXCHANGE;
    }
    
    return X25519_SUCCESS;
}


//计算客户端会话密钥（带密钥派生）
x25519_error_t x25519_client_session_keys(
    uint8_t rx_key[X25519_SESSION_KEY_SIZE],
    uint8_t tx_key[X25519_SESSION_KEY_SIZE],
    const uint8_t client_public[X25519_KEY_SIZE],
    const uint8_t client_secret[X25519_KEY_SIZE],
    const uint8_t server_public[X25519_KEY_SIZE]) {
    
    // 参数验证
    if (rx_key == NULL || tx_key == NULL ||
        client_public == NULL || client_secret == NULL ||
        server_public == NULL) {
        return X25519_ERROR_INVALID_PARAM;
    }
    
    // 步骤 1: 执行 X25519 密钥交换，计算共享密钥
    uint8_t shared_secret[X25519_KEY_SIZE];
    if (crypto_scalarmult_curve25519(shared_secret, client_secret, server_public) != 0) {
        return X25519_ERROR_KEY_EXCHANGE;
    }
    
    // 步骤 2: 使用自定义 HKDF-SHA256 派生会话密钥
    // 
    // HKDF 密钥派生过程：
    //   IKM (Input Key Material): X25519 共享密钥
    //   Salt: client_public || server_public （公钥拼接，用于区分不同会话）
    //   Info: 用于区分 rx_key 和 tx_key
    //   Output: 两个独立的 32 字节会话密钥
    //
    // 为什么需要 Salt？
    //   - 使用公钥作为 salt 可以绑定会话到特定的密钥对
    //   - 防止不同会话使用相同的派生密钥
    //   - 提供额外的安全保证
    //
    // 为什么需要不同的 Info？
    //   - rx_key 和 tx_key 必须是独立的密钥
    //   - 使用不同的 info 字符串可以派生出不同的密钥
    //   - 防止密钥重用攻击
    
    // 构造 Salt: client_public || server_public
    uint8_t salt[X25519_KEY_SIZE * 2];
    memcpy(salt, client_public, X25519_KEY_SIZE);
    memcpy(salt + X25519_KEY_SIZE, server_public, X25519_KEY_SIZE);
    
    // 派生 tx_key (客户端发送密钥)
    // Info: "x25519-client-tx" 标识客户端发送方向
    const char *tx_info = "x25519-client-tx";
    HKDF_SHA256(shared_secret, X25519_KEY_SIZE,
                salt, sizeof(salt),
                (const byte *)tx_info, strlen(tx_info),
                X25519_SESSION_KEY_SIZE, tx_key);
    
    // 派生 rx_key (客户端接收密钥)
    // Info: "x25519-client-rx" 标识客户端接收方向
    const char *rx_info = "x25519-client-rx";
    HKDF_SHA256(shared_secret, X25519_KEY_SIZE,
                salt, sizeof(salt),
                (const byte *)rx_info, strlen(rx_info),
                X25519_SESSION_KEY_SIZE, rx_key);
    
    // 步骤 3: 安全清除共享密钥
    sodium_memzero(shared_secret, sizeof(shared_secret));
    
    return X25519_SUCCESS;
}

x25519_error_t x25519_server_session_keys(
    uint8_t rx_key[X25519_SESSION_KEY_SIZE],
    uint8_t tx_key[X25519_SESSION_KEY_SIZE],
    const uint8_t server_public[X25519_KEY_SIZE],
    const uint8_t server_secret[X25519_KEY_SIZE],
    const uint8_t client_public[X25519_KEY_SIZE]) {
    
    // 参数验证
    if (rx_key == NULL || tx_key == NULL ||
        server_public == NULL || server_secret == NULL ||
        client_public == NULL) {
        return X25519_ERROR_INVALID_PARAM;
    }
    
    // 步骤 1: 执行 X25519 密钥交换，计算共享密钥
    uint8_t shared_secret[X25519_KEY_SIZE];
    if (crypto_scalarmult_curve25519(shared_secret, server_secret, client_public) != 0) {
        return X25519_ERROR_KEY_EXCHANGE;
    }
    
    // 步骤 2: 使用自定义 HKDF-SHA256 派生会话密钥
    // 
    // 关键点：服务端的密钥派生必须与客户端对应
    //   - Salt 必须相同：client_public || server_public
    //   - 但 Info 要交换：
    //     * server 的 tx_key 使用 "x25519-client-rx" (因为 server tx → client rx)
    //     * server 的 rx_key 使用 "x25519-client-tx" (因为 client tx → server rx)
    //
    // 这样确保：
    //   server.tx_key == client.rx_key
    //   server.rx_key == client.tx_key
    
    // 构造 Salt: client_public || server_public (与客户端相同)
    uint8_t salt[X25519_KEY_SIZE * 2];
    memcpy(salt, client_public, X25519_KEY_SIZE);
    memcpy(salt + X25519_KEY_SIZE, server_public, X25519_KEY_SIZE);
    
    // 派生 tx_key (服务端发送密钥)
    // 注意：使用 "x25519-client-rx" 因为服务端发送等于客户端接收
    const char *tx_info = "x25519-client-rx";
    HKDF_SHA256(shared_secret, X25519_KEY_SIZE,
                salt, sizeof(salt),
                (const byte *)tx_info, strlen(tx_info),
                X25519_SESSION_KEY_SIZE, tx_key);
    
    // 派生 rx_key (服务端接收密钥)
    // 注意：使用 "x25519-client-tx" 因为客户端发送等于服务端接收
    const char *rx_info = "x25519-client-tx";
    HKDF_SHA256(shared_secret, X25519_KEY_SIZE,
                salt, sizeof(salt),
                (const byte *)rx_info, strlen(rx_info),
                X25519_SESSION_KEY_SIZE, rx_key);
    
    // 步骤 3: 安全清除共享密钥
    sodium_memzero(shared_secret, sizeof(shared_secret));
    
    return X25519_SUCCESS;
}

/*
 * ============================================================================
 * 内存安全
 * ============================================================================
 */

void x25519_clear_key(void *key, size_t len) {
    if (key == NULL || len == 0) {
        return;
    }
    
    // 使用 libsodium 的安全清零函数
    // 
    // 为什么不用 memset？
    //   - 编译器可能会优化掉 memset(..., 0, ...) 调用
    //   - sodium_memzero 使用了特殊技巧保证内存一定会被清零
    //   - 防止敏感数据（如私钥、共享密钥）残留在内存中
    //
    // 安全实践：
    //   - 私钥使用完毕后立即清零
    //   - 共享密钥使用完毕后立即清零
    //   - 会话密钥使用完毕后立即清零
    sodium_memzero(key, len);
}

/*
 * ============================================================================
 * 辅助函数
 * ============================================================================
 */

const char* x25519_error_string(x25519_error_t error) {
    switch (error) {
        case X25519_SUCCESS:
            return "operation successful";
        case X25519_ERROR_INVALID_PARAM:
            return "invalid parameter (null pointer or invalid value)";
        case X25519_ERROR_KEY_EXCHANGE:
            return "key exchange failed (public key may be invalid)";
        case X25519_ERROR_INIT:
            return "initialization failed";
        case X25519_ERROR_KEYPAIR_GEN:
            return "keypair generation failed";
        default:
            return "unknown error";
    }
}

/*
 * ============================================================================
 * 实现说明
 * ============================================================================
 * 
 * 
 * 2. 两种 API 的选择：
 *    - x25519_exchange：低层 API，只计算原始共享密钥
 *      适用于需要自己进行密钥派生的场景
 *    
 *    - x25519_client/server_session_keys：高层 API，使用自定义 HKDF 进行密钥派生
 *      适用于建立加密通信会话的场景
 *      推荐在大多数情况下使用
 * 
 * 3. 密钥派生实现（使用自定义 HKDF-SHA256）：
 *    - IKM: X25519 计算的共享密钥
 *    - Salt: client_public || server_public (64 字节)
 *    - Info: 区分 rx/tx 的字符串标识
 *    - 输出: 两个独立的 32 字节会话密钥
 * 
 * 
 * 5. 安全注意事项：
 *    - 私钥必须保密，绝不能传输
 *    - 公钥可以公开，但应该进行认证（如使用数字签名）
 *    - 每次会话应该使用新的临时密钥对（前向保密）
 *    - 密钥使用完毕后立即清零
 *    - 共享密钥计算完成后立即派生并清除
 * 
 * 6. 与其他模块的集成：
 *    - ✓ 已集成自定义 HKDF-SHA256 进行密钥派生
 *    - 可以与 AES-GCM 或 AES-ETM 配合用于加密通信
 *    - 可以与 Ed25519 配合用于认证
 *    - 可以与 HMAC 配合进行消息认证
 *    - 派生的会话密钥可直接用于对称加密
 * 
 * 7. HKDF 参数说明：
 *    - Salt 使用公钥拼接，绑定到具体会话
 *    - Info 使用方向字符串，区分双向密钥
 *    - 输出长度固定为 32 字节（256 位），适合 AES-256 或 ChaCha20
 */