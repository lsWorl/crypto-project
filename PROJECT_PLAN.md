# 密码学学习项目路线图（1/13 - 2/1）

目标：在复试前完成一个具备工程化能力的密码学学习项目，覆盖对称密码、哈希/MAC、KDF、公钥与协议基础，并输出可展示的文档与测试体系。

## 总体阶段划分

### 第 1 周：对称密码 + 认证基础 + 工程化骨架
- 规划模块与接口（目录结构、头文件划分、错误码）。
- 引入已知测试向量（AES-CBC、HMAC-SHA256）。
- 预留分组模式入口（为 CTR/GCM 扩展做准备）。
- 文档：模式选择与 EtM 安全性说明。

### 第 2 周：公钥密码 + 密钥交换 + 混合加密演示
- RSA（OAEP / PSS）或 ECC（ECDH / ECDSA）择一优先实现。
- 实现 hybrid demo：公钥封装对称密钥 + 对称 AEAD。
- 文档：RSA 与 ECC 的对比、密钥交换流程。

### 第 3 周：协议化演示 + 测试/性能 + 答辩材料
- 简化 TLS/握手流程展示（步骤化）。
- 加入基准测试与简单性能评估。
- 输出复试展示材料（结构图、关键安全点说明）。

## 每日时间拆分（6-7 小时）
- 2.5h 代码实现与调试
- 1.5h 文档阅读与记录
- 1h 测试与验证（KAT/边界测试）
- 1h 复盘总结（形成答辩材料）

## 里程碑与可验收成果

### 里程碑 1（第 1 周结束）
- 模块化结构与接口草案完成。
- AES-CBC + HMAC-SHA256 具备测试向量。
- README 更新为路线图与说明。

### 里程碑 2（第 2 周结束）
- 公钥算法或密钥交换模块完成。
- hybrid demo 跑通。
- 文档产出：算法对比 + 流程解释。

### 里程碑 3（2/1 前）
- 协议化演示与基准测试完成。
- 复试可展示材料（图 + 文档）齐备。

## 下一步（本周第一步）
1. 新建模块目录（建议：include/crypto，src/crypto）。
2. 统一错误码与接口命名规范。
3. 增加测试向量文件与测试入口。

## 参考资料（建议阅读顺序）
- AES 标准（FIPS 197）：https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
- AES-CBC/CTR 等分组模式说明（SP 800-38A）：https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
- HMAC 标准（FIPS 198-1）：https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf
- SHA-256 标准（FIPS 180-4）：https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
- HKDF（RFC 5869）：https://www.rfc-editor.org/rfc/rfc5869
- GCM 模式（SP 800-38D）：https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
- RSA-OAEP/PSS（RFC 8017）：https://www.rfc-editor.org/rfc/rfc8017
- ECDSA（FIPS 186-5）：https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
