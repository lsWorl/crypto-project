#include "crypto/rng.h"
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#include <ntstatus.h>
#else
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#endif

// 使用系统的随机数生成器填充缓冲区
int crypto_random_bytes(byte *buf, size_t len){
    if(buf == NULL || len == 0){
        return -1; // 参数无效
    }
#ifdef _WIN32
    NTSTATUS status = BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if(status != STATUS_SUCCESS){
        return -1; // 生成随机数失败
    }
    return 0;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t r = read(fd, buf, len);
    close(fd);
    return (r == (ssize_t)len) ? 0 : -1;
#endif
}