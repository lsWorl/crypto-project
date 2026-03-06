# 密钥派生（PBKDF2 与 HKDF）模块说明

文件：`src/kdf.c`，头文件：`include/crypto/kdf.h`

本模块实现两类密钥派生函数：
1. PBKDF2-HMAC-SHA256（用于密码到主密钥的伸展）
2. HKDF-SHA256（用于从密钥材料导出多个子密钥）

一、PBKDF2-HMAC-SHA256
- 函数：`void pbkdf2_hmac_sha256(const byte *password, size_t password_len, const byte *salt, size_t salt_len, int iterations, size_t dk_len, byte *out_dk)`
- 原理：PBKDF2 使用 HMAC 作为 PRF，通过迭代（c 次）对盐 + 块索引做多次 HMAC，最终对每个输出块 Ti 做 XOR 累加所得。输出长度可任意，按 SHA-256 输出（32 字节）分块拼接。
- 实现要点：
  - 参数检查：迭代次数、派生长度、盐长度等进行基本验证并通过 `printf` 报错。
  - 内存：为每次块构造 salt||INT(i)（大端）并用于第一次 HMAC；后续迭代直接用上一轮 U 作为输入。
  - 性能：迭代次数越大越能提高抗暴力攻击成本，但同时影响合法用户延迟。

二、HKDF-SHA256
- 接口：`void HKDF_SHA256(const byte *ikm, size_t ikm_len, const byte *salt, size_t salt_len, const byte *info, size_t info_len, size_t okm_len, byte *out_okm)`
- 原理：HKDF 分为两步：Extract（使用 HMAC(salt, IKM) 生成 PRK）与 Expand（基于 PRK 和 info 迭代 HMAC 生成输出块）。
- 实现细节：
  - `hkdf_extract`：如果未提供盐（NULL 或长度 0），使用全零盐（等于哈希长度）；然后用 HMAC(salt, IKM) 生成 PRK（长度等于哈希长度，32 字节）。
  - `hkdf_expand`：迭代生成 N 块（N = ceil(okm_len/HashLen)），每块 T(i) = HMAC(PRK, T(i-1) || info || i)，并拼接前 okm_len 字节为最终 OKM。
  - 边界：若请求输出长度过长（N > 255）则返回错误。

项目中的用途
- 在 `src/x25519.c` 中：使用 X25519 共享密钥作为 IKM，公钥拼接作为 salt，分别以不同 info 字符串派生 tx/rx 密钥，保证双方派生一致且相互分离。
- 在 `src/file_crypto.c`：先用 PBKDF2 将密码扩展为 MASTER_KEY，再用 HKDF 派生用于 AES 加密和 HMAC 的独立密钥。

安全建议
- PBKDF2 的迭代次数应根据目标硬件调整（越高越安全但越慢），建议使用推荐值（如至少数万次或采用 Argon2 等更现代 KDF）。
- HKDF 的盐和 info 应合理选择以避免不同用途的密钥重用；项目中使用明确的 ascii 标签（如 "enc_key" / "hmac_key"）和上下文绑定盐。

测试
- 参考 `test/test_kdf.c` 中对 PBKDF2/HKDF 的示例与向量。
