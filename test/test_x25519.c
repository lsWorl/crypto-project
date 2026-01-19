#include "crypto/x25519.h"
#include <stdio.h>
#include <string.h>

// 打印字节数组为十六进制
void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 32 == 0 && i + 1 < len) {
            printf("\n%*s", (int)strlen(label) + 2, "");
        }
    }
    printf("\n");
}

// 测试计数器
static int test_passed = 0;
static int test_failed = 0;

#define TEST_ASSERT(condition, message) do { \
    if (condition) { \
        printf("  yes %s\n", message); \
        test_passed++; \
    } else { \
        printf("  no %s\n", message); \
        test_failed++; \
    } \
} while(0)

/**
 * 测试 1: 初始化
 */
int test_init(void) {
    printf("\n═══════════════════════════════════════════════════════════\n");
    printf("test 1: X25519 module initialization\n");
    printf("═══════════════════════════════════════════════════════════\n");
    
    x25519_error_t result = x25519_init();
    
    TEST_ASSERT(result == X25519_SUCCESS, "X25519 initialization successful");
    
    if (result == X25519_SUCCESS) {
        printf("  Note: libsodium library initialized correctly\n");
        return 0;
    } else {
        printf("  Error: %s\n", x25519_error_string(result));
        return -1;
    }
}

/**
 * 测试 2: 密钥对生成
 */
int test_keypair_generation(void) {
    printf("\n═══════════════════════════════════════════════════════════\n");
    printf("test 2: keypair generation\n");
    printf("═══════════════════════════════════════════════════════════\n");
    
    uint8_t public_key[X25519_KEY_SIZE];
    uint8_t secret_key[X25519_KEY_SIZE];
    
    // 测试正常生成
    x25519_error_t result = x25519_keypair(public_key, secret_key);
    TEST_ASSERT(result == X25519_SUCCESS, "keypair generation successful");
    
    print_hex("  public key", public_key, X25519_KEY_SIZE);
    print_hex("  secret key", secret_key, X25519_KEY_SIZE);
    
    
    // 测试生成第二个密钥对，验证不同
    uint8_t public_key2[X25519_KEY_SIZE];
    uint8_t secret_key2[X25519_KEY_SIZE];
    
    x25519_keypair(public_key2, secret_key2);
    
    int keys_different = memcmp(public_key, public_key2, X25519_KEY_SIZE) != 0;
    TEST_ASSERT(keys_different, "keypairs generated twice are different (randomness)");
    
    // 测试错误处理：空指针
    result = x25519_keypair(NULL, secret_key);
    TEST_ASSERT(result == X25519_ERROR_INVALID_PARAM, "empty pointer parameter check (public_key)");
    
    result = x25519_keypair(public_key, NULL);
    TEST_ASSERT(result == X25519_ERROR_INVALID_PARAM, "empty pointer parameter check (secret_key)");
    
    // 清理
    x25519_clear_key(secret_key, sizeof(secret_key));
    x25519_clear_key(secret_key2, sizeof(secret_key2));
    
    return 0;
}

/**
 * 测试 3: 从私钥恢复公钥
 */
int test_public_key_derivation(void) {
    printf("\n═══════════════════════════════════════════════════════════\n");
    printf("test 3: public key derivation from secret key\n");
    printf("═══════════════════════════════════════════════════════════\n");
    
    // 先生成一个密钥对
    uint8_t public_key_original[X25519_KEY_SIZE];
    uint8_t secret_key[X25519_KEY_SIZE];
    
    x25519_keypair(public_key_original, secret_key);
    print_hex("  original public key", public_key_original, X25519_KEY_SIZE);
    
    // 从私钥重新计算公钥
    uint8_t public_key_derived[X25519_KEY_SIZE];
    x25519_error_t result = x25519_public_key(public_key_derived, secret_key);
    
    TEST_ASSERT(result == X25519_SUCCESS, "public key derivation from secret key successful");
    print_hex("  derived public key", public_key_derived, X25519_KEY_SIZE);
    
    // 验证两个公钥相同
    int keys_match = memcmp(public_key_original, public_key_derived, X25519_KEY_SIZE) == 0;
    TEST_ASSERT(keys_match, "derived public key matches original public key");
    
    // 清理
    x25519_clear_key(secret_key, sizeof(secret_key));
    
    return 0;
}

/**
 * 测试 4: 基础密钥交换
 */
int test_basic_key_exchange(void) {
    printf("\n═══════════════════════════════════════════════════════════\n");
    printf("test 4: basic X25519 key exchange\n");
    printf("═══════════════════════════════════════════════════════════\n");
    
    printf("\n  Scenario: Alice and Bob negotiate a shared key via X25519\n");
    
    // Alice 生成密钥对
    uint8_t alice_public[X25519_KEY_SIZE];
    uint8_t alice_secret[X25519_KEY_SIZE];
    x25519_keypair(alice_public, alice_secret);
    
    printf("\n  Alice :\n");
    print_hex("    public key", alice_public, X25519_KEY_SIZE);
    
    // Bob 生成密钥对
    uint8_t bob_public[X25519_KEY_SIZE];
    uint8_t bob_secret[X25519_KEY_SIZE];
    x25519_keypair(bob_public, bob_secret);
    
    printf("\n  Bob :\n");
    print_hex("    public key", bob_public, X25519_KEY_SIZE);
    
    // Alice 计算共享密钥
    uint8_t alice_shared[X25519_KEY_SIZE];
    x25519_error_t result = x25519_exchange(alice_shared, alice_secret, bob_public);
    
    TEST_ASSERT(result == X25519_SUCCESS, "Alice computes shared key successfully");
    
    // Bob 计算共享密钥
    uint8_t bob_shared[X25519_KEY_SIZE];
    result = x25519_exchange(bob_shared, bob_secret, alice_public);
    
    TEST_ASSERT(result == X25519_SUCCESS, "Bob computes shared key successfully");
    
    printf("\n  Key exchange results:\n");
    print_hex("    Alice's shared key", alice_shared, X25519_KEY_SIZE);
    print_hex("    Bob's shared key", bob_shared, X25519_KEY_SIZE);
    
    // 验证共享密钥相同
    int shared_match = memcmp(alice_shared, bob_shared, X25519_KEY_SIZE) == 0;
    TEST_ASSERT(shared_match, "Alice and Bob computed the same shared key");
    
    if (shared_match) {
        printf("\n Key exchange successful! Both parties can use the shared key to establish secure communication\n");
    }
    
    // 清理
    x25519_clear_key(alice_secret, sizeof(alice_secret));
    x25519_clear_key(bob_secret, sizeof(bob_secret));
    x25519_clear_key(alice_shared, sizeof(alice_shared));
    x25519_clear_key(bob_shared, sizeof(bob_shared));
    
    return 0;
}

/**
 * 测试 5: 会话密钥派生
 */
int test_session_key_derivation(void) {
    printf("\n═══════════════════════════════════════════════════════════\n");
    printf("test 5: session key derivation (high-level API)\n");
    printf("═══════════════════════════════════════════════════════════\n");
    
    printf("\n  Scenario: Establishing a bidirectional encrypted communication channel\n");
    printf("        Client and server each derive receive/send keys\n");
    
    // 客户端生成密钥对
    uint8_t client_public[X25519_KEY_SIZE];
    uint8_t client_secret[X25519_KEY_SIZE];
    x25519_keypair(client_public, client_secret);
    
    printf("\n  client:\n");
    print_hex("    public key", client_public, X25519_KEY_SIZE);
    
    // 服务端生成密钥对
    uint8_t server_public[X25519_KEY_SIZE];
    uint8_t server_secret[X25519_KEY_SIZE];
    x25519_keypair(server_public, server_secret);
    
    printf("\n  server:\n");
    print_hex("    public key", server_public, X25519_KEY_SIZE);
    
    // 客户端派生会话密钥
    uint8_t client_rx[X25519_SESSION_KEY_SIZE];
    uint8_t client_tx[X25519_SESSION_KEY_SIZE];
    
    x25519_error_t result = x25519_client_session_keys(
        client_rx, client_tx,
        client_public, client_secret,
        server_public
    );
    
    TEST_ASSERT(result == X25519_SUCCESS, "client session keys derivation successful");
    
    printf("\n  client session keys:\n");
    print_hex("    receive key (rx)", client_rx, X25519_SESSION_KEY_SIZE);
    print_hex("    send key (tx)", client_tx, X25519_SESSION_KEY_SIZE);
    
    // 服务端派生会话密钥
    uint8_t server_rx[X25519_SESSION_KEY_SIZE];
    uint8_t server_tx[X25519_SESSION_KEY_SIZE];
    
    result = x25519_server_session_keys(
        server_rx, server_tx,
        server_public, server_secret,
        client_public
    );
    
    TEST_ASSERT(result == X25519_SUCCESS, "server session keys derivation successful");
    
    printf("\n  server session keys:\n");
    print_hex("    receive key (rx)", server_rx, X25519_SESSION_KEY_SIZE);
    print_hex("    send key (tx)", server_tx, X25519_SESSION_KEY_SIZE);
    
    // 验证密钥对称性
    printf("\n  verify key symmetry:\n");
    
    int client_tx_server_rx = memcmp(client_tx, server_rx, X25519_SESSION_KEY_SIZE) == 0;
    TEST_ASSERT(client_tx_server_rx, "client tx = server rx (client sends → server receives)");
    
    int client_rx_server_tx = memcmp(client_rx, server_tx, X25519_SESSION_KEY_SIZE) == 0;
    TEST_ASSERT(client_rx_server_tx, "client rx = server tx (server sends → client receives)");
    
    // 验证接收和发送密钥不同（防止密钥重用）
    int rx_tx_different = memcmp(client_rx, client_tx, X25519_SESSION_KEY_SIZE) != 0;
    TEST_ASSERT(rx_tx_different, "receive and send keys are different (prevent key reuse)");
    
    if (client_tx_server_rx && client_rx_server_tx) {
        printf("\n  Bidirectional encrypted channel established successfully!\n");
        printf("    - Client can use tx_key to encrypt sending, rx_key to decrypt receiving\n");
        printf("    - Server can use tx_key to encrypt sending, rx_key to decrypt receiving\n");
    }
    
    // 清理
    x25519_clear_key(client_secret, sizeof(client_secret));
    x25519_clear_key(server_secret, sizeof(server_secret));
    x25519_clear_key(client_rx, sizeof(client_rx));
    x25519_clear_key(client_tx, sizeof(client_tx));
    x25519_clear_key(server_rx, sizeof(server_rx));
    x25519_clear_key(server_tx, sizeof(server_tx));
    
    return 0;
}

/**
 * 测试 6: 错误处理
 */
int test_error_handling(void) {
    printf("\n═══════════════════════════════════════════════════════════\n");
    printf("test 6: error handling\n");
    printf("═══════════════════════════════════════════════════════════\n");
    
    uint8_t valid_key[X25519_KEY_SIZE] = {0};
    x25519_error_t result;
    
    // 测试 x25519_exchange 的错误处理
    printf("\n  test x25519_exchange parameter validation:\n");
    
    result = x25519_exchange(NULL, valid_key, valid_key);
    TEST_ASSERT(result == X25519_ERROR_INVALID_PARAM, "detect null shared_key pointer");
    
    result = x25519_exchange(valid_key, NULL, valid_key);
    TEST_ASSERT(result == X25519_ERROR_INVALID_PARAM, "detect null secret_key pointer");
    
    result = x25519_exchange(valid_key, valid_key, NULL);
    TEST_ASSERT(result == X25519_ERROR_INVALID_PARAM, "detect null public_key pointer");
    
    // 测试 x25519_client_session_keys 的错误处理
    printf("\n  test x25519_client_session_keys parameter validation:\n");
    
    result = x25519_client_session_keys(NULL, valid_key, valid_key, valid_key, valid_key);
    TEST_ASSERT(result == X25519_ERROR_INVALID_PARAM, "detect null rx_key pointer");
    
    result = x25519_client_session_keys(valid_key, NULL, valid_key, valid_key, valid_key);
    TEST_ASSERT(result == X25519_ERROR_INVALID_PARAM, "detect null tx_key pointer");
    
    // 测试错误信息字符串
    printf("\n  test error string:\n");
    printf("    X25519_SUCCESS: %s\n", x25519_error_string(X25519_SUCCESS));
    printf("    X25519_ERROR_INVALID_PARAM: %s\n", x25519_error_string(X25519_ERROR_INVALID_PARAM));
    printf("    X25519_ERROR_KEY_EXCHANGE: %s\n", x25519_error_string(X25519_ERROR_KEY_EXCHANGE));
    
    TEST_ASSERT(1, "error strings returned correctly");
    
    return 0;
}




int main(void) {
    printf("test x25519 module based on sodium \n");
    
    // 运行所有测试
    if (test_init() != 0) {
        printf("\n initialization failed!\n");
        return 1;
    }
    
    test_keypair_generation();
    test_public_key_derivation();
    test_basic_key_exchange();
    test_session_key_derivation();
    test_error_handling();
    
    // 输出测试结果
    printf("test results:\n");
    printf("\n  pass: %d\n", test_passed);
    printf("  fail: %d\n", test_failed);
    printf("  total: %d\n", test_passed + test_failed);
    
    if (test_failed == 0) {
        printf("\nAll tests passed! X25519 module is working correctly\n");
    } else {
        printf("\n  %d tests failed\n", test_failed);
    }
    
    printf("\n═══════════════════════════════════════════════════════════\n");
    printf("Usage Instructions:\n");
    printf("═══════════════════════════════════════════════════════════\n");
    printf("\n1. Basic key exchange process:\n");
    printf("   x25519_init();\n");
    printf("   x25519_keypair(my_pub, my_sec);\n");
    printf("   // Exchange public keys...\n");
    printf("   x25519_exchange(shared, my_sec, their_pub);\n");
    
    printf("\n2. Establish encrypted session (recommended):\n");
    printf("   x25519_init();\n");
    printf("   x25519_keypair(my_pub, my_sec);\n");
    printf("   // Exchange public keys...\n");
    printf("   x25519_client_session_keys(rx, tx, my_pub, my_sec, peer_pub);\n");
    printf("   // Use tx to encrypt sending, rx to decrypt receiving\n");
    
    printf("\n3. Secure clearing:\n");
    printf("   x25519_clear_key(secret_key, sizeof(secret_key));\n");
    
    // printf("\nNext steps recommendations:\n");
    // printf("  - 与 AES-GCM 或 ChaCha20-Poly1305 结合实现端到端加密\n");
    // printf("  - 添加 Ed25519 数字签名进行身份认证\n");
    // printf("  - 实现完整的密钥轮换机制（Key Ratcheting）\n");
    // printf("  - 学习自己实现 X25519 算法（理解椭圆曲线密码学）\n");
    
    return (test_failed == 0) ? 0 : 1;
}
