# 随机数生成（RNG）模块说明

文件：`src/rng.c`，头文件：`include/crypto/rng.h`

概述
- 本模块提供 `crypto_random_bytes(byte *buf, size_t len)`，用于从操作系统获取高质量随机字节。

实现细节
- 在 Windows 平台上（`_WIN32`）：使用 Windows CNG API `BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG)`，这是推荐的系统随机源（使用系统偏好的 RNG）。
- 在类 Unix 系统上：打开 `/dev/urandom` 并读取所需字节，随后关闭文件描述符。

返回值
- 成功返回 0，失败返回 -1（例如参数无效、系统调用失败等）。

安全注意
- 使用系统提供的随机源是安全实践；不要尝试自行实现伪随机生成器来替代系统熵源。
- 在某些平台（如早期嵌入式或裸机环境），可能没有 `/dev/urandom` 或等价接口，需要额外适配或依赖硬件 RNG。

建议
- 对关键长短期密钥或 IV 推荐使用本函数获取随机数据。
- 若需要可审计的 RNG（并非仅依赖 OS），可以在上层对生成结果做熵混合或使用 libsodium 的高层 API。
