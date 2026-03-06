# 测试与验证文档

目录：`test/` 下包含多个测试文件，针对各模块进行功能性与向量验证。

测试文件一览
- `test_sha256.c`：使用已知 SHA-256 向量验证 `sha256()` 实现。
- `test_hmac_sha256.c`：以已知向量验证 HMAC 输出。
- `test_kdf.c`：包含 PBKDF2 的迭代示例与 HKDF 展开演示。
- `test_x25519.c`：生成密钥对、计算共享秘密并对比，验证会话键派生一致性。
- `test_AES.c`：验证单块 AES 加解密与 CBC 模式的正确性。
- `test_etm.c` 与 `test_etm_file.c`：验证 ETM 模式生成/校验 HMAC，以及文件级 ETM 封装的加解密完整性。
- `test_file_crypto.c` / `test_file_crypto_final.c`：端到端加解密示例，包含对文件头（迭代次数/盐）与明文恢复的检验。

测试向量
- 测试目录包含 `vectors.h`，其中存放用于各项测试的固定输入与期望输出（如 SHA-256 向量、HMAC 示例、密钥/消息对等）。

如何运行测试（示例）
```powershell
mkdir build
cd build
cmake ..
cmake --build .
ctest
# 或直接运行单个测试二进制：
# ./test_sha256.exe
```

测试建议
- 在修改实现后首先运行对应模块的单元测试以快速定位回归问题。
- 考虑为异常条件（如损坏文件、错误密钥、无效填充）加入更多负面测试用例。
