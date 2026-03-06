# AES 模块说明

目录：`AES/` 中包含以下源文件（实现细节见源文件注释）
- `AESEncryption.c`：加密流程、SubBytes/ShiftRows/MixColumns、CBC 模式、ETM 加密封装
- `AESDecryption.c`：解密流程、逆变换、CBC 解密、ETM 解密封装
- `common.c`：状态矩阵、S-box/InvSbox、密钥扩展相关常量与工具、PKCS#7 填充函数

实现概述
- 本项目实现经典的 AES-128（128 位密钥、16 字节块）算法：
  - 轮数 `Nr` = 10，密钥扩展生成 `roundKeys`。
  - Block 处理使用列主序（state[4][4]），并在最终输出时按列到字节流转换。

核心变换
- SubBytes：基于 S-box 的字节替代（非线性层）。
- ShiftRows：对行循环移位以实现跨列扩散。
- MixColumns：在有限域 GF(2^8) 上进行线性混合，实现列间扩散；使用 `xtime` 与 `mul_by_03` 等工具函数。
- AddRoundKey：将轮密钥与状态异或。
- 逆操作在解密模块中实现（InvSBox, inv_shift_rows, inv_mix_columns）。

模式与填充
- CBC（Cipher Block Chaining）模式实现：`encrypt_cbc` 与 `decrypt_cbc`，使用 IV 与逐块异或。
- 填充采用 PKCS#7：`pkcs7_pad` 与 `pkcs7_unpad` 在 `common.c` 中实现；加密前要做填充，解密后要验证并移除填充。

ETM（Encrypt-then-MAC）封装
- `encrypt_etm`：生成/使用 IV，加密（CBC + PKCS#7），然后对 `IV||ciphertext` 计算 HMAC-SHA256 并附加在输出末尾（HMAC key 由上层传入或派生）。输出格式：IV || Ciphertext || TAG。
- `decrypt_etm`：先提取并验证 HMAC（常量时间比较），再进行 CBC 解密与去填充；若 HMAC 验证失败则拒绝解密以避免欺骗。

实现注意事项
- 内存管理：某些函数在示例实现中分配了临时缓冲但注释了释放（需注意内存泄漏问题并在必要处 free）。
- 常量时间：做 MAC 校验与密钥清零时应注意常量时间与安全擦除（项目使用 `ct_equal` 与 `sodium_memzero` 在部分位置）。
- AES-128：当前实现仅支持 128 位密钥，若需 192/256 需改密钥扩展和轮数（并测试向量）。

测试
- `test/test_AES.c` 对基本块加解密与 CBC 模式进行验证。

参考
- FIPS 197: Advanced Encryption Standard
- PKCS#7 填充规范
