CC=gcc
CFLAGS=-I. -Iinclude -IAES -Isrc -Itest -Wall -Wextra -g
# 链接库：bcrypt用于随机数，libsodium.a用于高级加密算法
LIBS=-lbcrypt
SODIUM_LIB=libsodium.a
SRCS=$(wildcard src/*.c)
OBJS=$(SRCS:.c=.o)
LIB=libcrypto.a

.PHONY: all clean test run-tests

all: $(LIB)

$(LIB): $(OBJS)
	ar rcs $@ $^

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

test: $(LIB)
	$(CC) $(CFLAGS) -o test_hmac test/test_hmac_sha256.c $(LIB) $(LIBS)
	$(CC) $(CFLAGS) -o test_etm test/test_etm.c AES/AESEncryption.c AES/AESDecryption.c AES/common.c $(LIB) $(LIBS)
	$(CC) $(CFLAGS) -o test_etm_file test/test_etm_file.c AES/AESEncryption.c AES/AESDecryption.c AES/common.c $(LIB) $(LIBS)
	$(CC) $(CFLAGS) -o test_AES test/test_AES.c AES/AESEncryption.c AES/AESDecryption.c AES/common.c $(LIB) $(LIBS)
	$(CC) $(CFLAGS) -o test_kdf test/test_kdf.c AES/AESEncryption.c AES/AESDecryption.c AES/common.c $(LIB) $(LIBS)
	$(CC) $(CFLAGS) -o test_file_crypto test/test_file_crypto.c AES/AESEncryption.c AES/AESDecryption.c AES/common.c $(LIB) $(LIBS)
	$(CC) $(CFLAGS) -o test_x25519 test/test_x25519.c $(LIB) $(SODIUM_LIB) $(LIBS)
	@echo "Built test_hmac, test_etm, test_etm_file, test_AES, test_kdf, test_file_crypto, test_x25519"

run-tests: test
	@echo "Running tests..."
	@test_hmac.exe || (echo "test_hmac failed" & exit 1)
	@test_etm.exe || (echo "test_etm failed" & exit 1)
	@test_etm_file.exe || (echo "test_etm_file failed" & exit 1)
	@test_file_crypto.exe
	@echo "All tests executed"

clean:
	del /Q src\*.o $(LIB) test_*.exe 2>nul || echo Clean completed
