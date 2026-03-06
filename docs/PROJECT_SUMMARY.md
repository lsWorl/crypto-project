# 加密项目总结

本文档对仓库中的加密代码进行了详细概述，旨在供密码学复试或学术场景下的审阅使用。项目组织为一个小型的加密库，附带单元测试和示例文件加密工具。

---

## 仓库结构

`
crypto/                # 顶层项目目录
├── AES/               # AES 实现及辅助代码
├── include/           # 公共头文件（sodium 封装、crypto API）
├── src/               # 核心密码原语和工具的 C 实现
├── test/              # 每个模块的单元测试
├── docs/              # 文档（本文件）
├── build/             # CMake/Make 构建产物
├── examples/          # 示例（当前为空）
├── CMakeLists.txt     # 构建配置
├── Makefile           # 备用构建系统
└── README.md
`

AES/ 下包含独立的密码实现，可被上层模块调用。src/ 目录包含哈希、密钥派生、随机数生成、密钥交换和文件加密的实现。测试代码调用各 API 并作为用法参考。

---

## 核心模块

### 1. SHA‑256（src/sha256.c，include/crypto/sha256.h）

- 按照 FIPS 180‑4 完整实现 SHA‑256 哈希函数。
- 常量（初始哈希值、轮常数）来自规范。
- 函数：
  - sha256() 计算输入缓冲区的 32 字节摘要。
  - sha256_print() 以十六进制打印摘要。
- 实现包含消息填充、大端字处理和压缩函数，使用 ROTRIGHT、CH、MAJ、EP0、EP1、SIG0、SIG1 等辅助宏。

### 2. HMAC‑SHA256（src/hmac.c，include/crypto/hmac.h）

- 使用 SHA‑256 实现 HMAC 构造。
- 针对超过块大小的密钥先哈希；不足则用零填充。
- 导出 hmac_sha256()，生成 32 字节标签。

### 3. 密钥派生

#### PBKDF2‑HMAC‑SHA256（src/kdf.c）

- 基于密码的密钥派生，可配置迭代次数。
- 使用标准 FIPS 800‑108 风格循环产生任意长度派生密钥。
- 对参数进行基本验证，错误通过 printf 报告。

#### HKDF‑SHA256（src/kdf.c）

- 两阶段 extract/expand 实现。
- 对外接口为 HKDF_SHA256()；内部有 hkdf_extract 和 hkdf_expand。
- 对零长度盐值用全零替代。
- 该函数在 X25519 会话密钥派生等处使用。

### 4. 随机数生成（src/rng.c，include/crypto/rng.h）

- crypto_random_bytes() 从操作系统的熵源填充缓冲区。
- Windows 上使用 BCryptGenRandom 并指定 BCRYPT_USE_SYSTEM_PREFERRED_RNG。
- 类 Unix 系统读取 /dev/urandom。

### 5. X25519 密钥交换（src/x25519.c，include/crypto/x25519.h）

- 基于 libsodium 的薄封装（crypto_kx_*、crypto_scalarmult_curve25519）。
- 提供：
  - x25519_init() 初始化 libsodium。
  - x25519_keypair() 和 x25519_public_key() 生成密钥对。
  - x25519_exchange() 执行原始 DH。
  - x25519_client_session_keys() 与 x25519_server_session_keys() 使用 HKDF‑SHA256 从共享秘密派生一对 32 字节会话密钥（rx/tx）；代码注释说明盐与 info 字符串的选择如何保证客户端/服务端对称。
- 错误码在头文件中通过 x25519_error_t 定义。

### 6. 文件加密（src/file_crypto.c，include/crypto/file_crypto.h）

- 组合 PBKDF2、HKDF、AES‑ETM 实现基于密码的文件加密/解密。
- 加密文件格式：4 字节大端迭代次数 + 盐值 + AES‑ETM 数据块（IV‖密文‖HMAC）。
- encrypt_file_HKDF() 生成随机盐，通过 PBKDF2 得到主密钥，再用 HKDF 派生加密和 MAC 密钥。
- decrypt_file_HKDF() 逆过程并验证完整性。
- 使用 AES 库的 ETM 辅助函数。

### 7. AES 实现（AES/ 目录）

- 经典 128 位 AES，包含 SubBytes（S 盒）、ShiftRows、MixColumns 及密钥扩展。
- 提供单个 16 字节块的 encrypt()/decrypt()。
- CBC 模式助手 encrypt_cbc()/decrypt_cbc()。
- 加密‑先‑认证（ETM）函数 encrypt_etm()/decrypt_etm() 生产/消费 IV‖密文‖HMAC 格式，使用 HMAC‑SHA256。
- 文件级包装 encrypt_file()/decrypt_file() 和 encrypt_file_etm()/decrypt_file_etm()。
- 代码通过 crypto_random_bytes() 生成随机 IV。

---

## 头文件组织

所有公共接口均声明在 include/crypto/*.h 下。例如：

- sha256.h 声明哈希相关常量和原型。
- hmac.h 声明 HMAC 函数。
- kdf.h 包含 PBKDF2 与 HKDF 原型。
- ng.h 提供随机字节函数。
- x25519.h 定义密钥交换类型和函数。
- ile_crypto.h 提供高级文件加密 API。

AES/ 下的头文件（AESEncryption.h、AESDecryption.h、common.h）定义了 AES 代码使用的内部状态和常量，被 src/ 模块包含。

---

## 测试（	est/）

每个密码组件都有对应的单元测试：

- 	est_sha256.c – 验证 SHA‑256 的已知向量。
- 	est_hmac_sha256.c – 使用标准向量测试 HMAC。
- 	est_kdf.c – 演示 PBKDF2 和 HKDF。
- 	est_x25519.c – 生成密钥对并确认共享秘密相同；测试会话密钥派生。
- 	est_file_crypto.c、	est_file_crypto_final.c – 加解密示例文件并验证。
- 	est_AES.c – 检查 AES 块加解密、CBC 模式。
- 	est_etm.c 与 	est_etm_file.c – 验证 ETM 模式和文件封装。

测试中包含 ectors.h 头文件，存储常量测试数据。

---

## 构建与使用

- 项目使用 CMake 和 Makefile；运行 cmake 或 make 可构建库和测试。
- 示例命令（在工作目录根）：
  `powershell
  mkdir build && cd build
  cmake ..
  cmake --build .
  ctest    # 或直接运行构建目录下的测试可执行文件
  `
- include/ 下的头文件允许外部项目包含本库的 API。

---

## 安全说明

- 本库为教学用途，不适合直接投入生产。部署前请仔细审查。
- AES 仅实现 128 位密钥；扩展到 192/256 需修改密钥调度逻辑。
- PBKDF2/HKDF 实现符合标准，但错误报告使用 printf，HMAC 之外未做常量时
  间比较。
- 随机性依赖操作系统；某些平台可能需要额外初始化。
- X25519 函数封装 libsodium，链接时须包含相应库。

---

## 总结

仓库实现了一套连贯的密码原语：哈希、消息认证、密钥派生、对称加密（AES‑CBC 和 ETM）以及基于 libsodium 的 X25519 非对称密钥交换。高层文件加密工具展示了如何组合这些原语以实现基于密码的
加密并保证完整性。完整的单元测试覆盖每个模块，可作为复习或进一步开发的起点。

此文档应当帮助你在密码学复试中讨论设计决策、算法细节和你的实现。
