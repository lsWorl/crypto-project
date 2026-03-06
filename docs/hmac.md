# HMAC-SHA256 模块说明

文件：`src/hmac.c`，头文件：`include/crypto/hmac.h`

概述
- 本模块实现 HMAC（Hash-based Message Authentication Code），使用内部的 SHA-256 实现作为底层哈希函数。
- HMAC 用于消息完整性与认证，输出 32 字节（SHA-256 输出长度）。

主要函数
- `void hmac_sha256(const byte *key, size_t key_len, const byte *message, size_t message_len, byte *out_digest)`
  - 输入：密钥、消息及其长度
  - 输出：32 字节 MAC 写入 `out_digest`

实现细节
- 块大小：对 SHA-256，块大小 `HMAC_BLOCK_SIZE`=64 字节。
- 密钥处理：
  - 若密钥长度 > 64，则先对密钥做 SHA-256，得到 32 字节，再补零至 64 字节；
  - 若密钥长度 <= 64，则直接复制并用零填充至 64 字节。
- ipad/opad：
  - 构造 `i_key_pad = key_block ^ 0x36`，`o_key_pad = key_block ^ 0x5c`。
- 计算流程：
  - 内层哈希：H(i_key_pad || message)
  - 外层哈希：H(o_key_pad || inner_hash)
  - 最终输出 outer 哈希结果作为 HMAC 值。

实现注意点
- 函数在内存中使用栈缓冲区（如 `key_block`, `i_key_pad`, `o_key_pad`），消息较大时未做流式 HMAC；当前实现将内外层串联数据放入临时缓冲区后调用 `sha256`，对大消息可能占用较多栈/堆内存。
- HMAC 是常用的 MAC 构造：其安全性基于底层哈希的抗碰撞/伪随机特性及密钥机密性。

安全建议
- 为防止时序泄露，检测/比较 MAC 时应使用常量时间比较函数（项目中在 ETM 解密路径使用 `ct_equal`）；调用端在比较 HMAC 值时也应使用常量时间比较。
- 不要重用密钥做其他非认证目的，按需要使用独立派生的 MAC 密钥（项目中采用 HKDF 派生 MAC/enc 密钥）。

测试
- 请查看 `test/test_hmac_sha256.c` 中的测试向量以验证实现。