运行该程序命令：gcc -g main.c common.c AESEncryption.c -o main.exe 2>&1  （采用GCC编译器，会产生main.exe文件）
然后再运行：main.exe

对应论文地址为https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
状态向量采用Appendix B中的测试向量
代码中encrypt和decrypt为论文复现
## 任意字长的明文加密说明
填充采用PKCS#7，填充规则为：（）
    如果数据长度正好是块大小的整数倍 → 补一个完整的块，这个块的每个字节都等于块大小的值。
    如果数据长度不足一块 → 补上需要的字节数，每个补上的字节值都等于需要补的字节数。

分组模式采用CBC，每个明文块先与前一密文块异或，再用密钥加密，具有良好的扩散性（ECB为直接为每个明文块加密，容易被分析，故采用CBC,因为只用于学习原理，IV向量只通过简单的rand函数实现）

### 组合方式的选择
采用Encrypt-then-MAC，相比于其他更加安全
MAC-then-Encrypt在解密时是先解密密文再检查padding，会出现padding oracle attack
Encrypt-and-MAC可能会泄露明文部分信息

引入SHA256，SHA256具有：
单向性：无法从哈希值推导出原始消息。
碰撞抗性：不同的输入不应该产生相同的哈希值。
定长输出：无论输入多长，输出始终是 256 位。

**测试采用恒定时间比较，避免定时攻击**

**采用密钥分离，HMAC与加密采用不同密钥**

Crypto skeleton

This folder contains the skeleton for AES-CBC + HMAC-SHA256 Encrypt-then-MAC (EtM).

Layout:
- include/crypto: public headers
- src: implementation stubs
- test: simple test scaffolding
- CMakeLists.txt: minimal CMake configuration

