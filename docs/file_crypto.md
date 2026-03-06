# 文件加密（File Crypto）模块说明

文件：`src/file_crypto.c`，头文件：`include/crypto/file_crypto.h`

概述
- 本模块提供基于密码的文件加密/解密接口，组合 PBKDF2、HKDF、AES-ETM（Encrypt-then-MAC）来实现保密性与完整性。
- 加密文件格式（项目中约定）：
  - 4 字节大端迭代次数（PBKDF2 iterations），
  - SALT（固定长度 `SALT_SIZE`），
  - 后续为 ETM 数据：IV || Ciphertext || HMAC

主要函数
- `int encrypt_file_HKDF(const char *input_path, const char *output_path, const char *password, size_t pass_len, size_t iterations)`
  - 生成随机盐 `salt`，用 PBKDF2(password, salt, iterations) 生成 `master_key`（固定长度），再用 HKDF 从 `master_key` 派生加密密钥与 MAC 密钥（`enc_key`, `hmac_key`）。
  - 生成随机 IV，使用 AES-CBC + PKCS#7 填充对文件数据加密，然后对 `IV||ciphertext` 计算 HMAC（HMAC-SHA256），输出 `iter||salt||IV||ciphertext||hmac`。
- `int decrypt_file_HKDF(const char *input_path, const char *output_path, const char *password, size_t pass_len)`
  - 读取 iterations 与 salt，重现 `master_key`，用 HKDF 得到 `enc_key` 与 `hmac_key`，对 ETM 数据先验证 HMAC，再解密并移除填充，最终写出明文文件。

AES-ETM 说明
- ETM = Encrypt-then-MAC：先对明文加密（使用 AES-CBC + PKCS#7），然后计算 HMAC 覆盖 IV 与密文，接收方先验证 HMAC（常量时间比较），再解密。
- ETM 是推荐的对称加密认证模式，因为其在验证失败时不会泄露解密侧信息。

实现注意点
- 密钥派生：PBKDF2 用于将低熵密码提升为固定长度 `MASTER_KEY`，HKDF 则从该主密钥派生不同用途的子密钥以避免密钥重用。
- 文件格式设计：预置迭代次数与盐使得解密方能重复派生相同主密钥；将这两项作为文件头是常见做法，但必须保护盐与迭代次数不会被篡改（若需要篡改检测，则需全文件签名或基于密钥派生的完整性绑定）。
- 错误处理：当前实现通过打印并返回 -1 报告错误；生产环境建议更明确的错误码与日志策略。

安全建议
- 迭代次数应根据目标平台选择高于最小值以增加暴力破解成本。可以考虑使用比 PBKDF2 更安全的 Argon2 作为现代替代。
- 永远使用独立的加密/认证密钥（本项目通过 HKDF 实现）。
- 在对 HMAC 做比较时使用常量时间比较函数以避免时序攻击（实现中 `decrypt_etm` 使用 `ct_equal`）。

测试
- 参见 `test/test_file_crypto.c`、`test/test_file_crypto_final.c` 和 `test/test_etm_file.c` 以验证整个加密/解密流程。
