# 密码学项目

目标：覆盖对称密码、哈希/MAC、KDF、公钥与协议基础，并有特定测试体系。

## 总体阶段划分

### 第 1 周：对称密码 + 认证基础 + 工程化骨架
- 规划模块与接口（目录结构、头文件划分）。
- 引入已知测试向量（AES-CBC、HMAC-SHA256）。
- 预留分组模式入口（为 CTR/GCM 扩展做准备）。
- 添加密码派生KDF模块,采用两层KDF，第一层采用用户密码（低熵），经PBKDF2-HMAC-SHA256(加盐和多轮，防止字典攻击)形成Master Key（高熵）再通过HKDF-SHA256(密钥分离，用于加密密钥，MAC密钥，以及IV seed)
- 文档：模式选择与 EtM 安全性说明。

### 第 2 周：公钥密码 + 密钥交换 + 混合加密演示
- RSA（OAEP / PSS）或 ECC（ECDH / ECDSA）择一优先实现。
- 实现 hybrid demo：公钥封装对称密钥 + 对称 AEAD。
- 文档：RSA 与 ECC 的对比、密钥交换流程。

### 第 3 周：协议化演示 + 测试/性能
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


## 参考资料（建议阅读顺序）
- AES 标准（FIPS 197）：https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
- AES-CBC/CTR 等分组模式说明（SP 800-38A）：https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
- HMAC 标准（FIPS 198-1）：https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf
- SHA-256 标准（FIPS 180-4）：https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
- PBKDF2 (RFC2898) https://www.rfc-editor.org/rfc/rfc2898 https://datatracker.ietf.org/doc/html/rfc7914(11节中有用于PBKDF2 with HMAC-SHA256的测试向量)
- HKDF（RFC 5869）：https://www.rfc-editor.org/rfc/rfc5869
- GCM 模式（SP 800-38D）：https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
- RSA-OAEP/PSS（RFC 8017）：https://www.rfc-editor.org/rfc/rfc8017
- ECDSA（FIPS 186-5）：https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf