CC=gcc
CFLAGS=-I. -Iinclude -IAES -Isrc -Itest -Wall -Wextra -g
LIBS=-lbcrypt
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
	@echo "Built test_hmac, test_etm, test_etm_file, test_AES, test_kdf"

run-tests: test
	@echo "Running tests..."
	@test_hmac.exe || (echo "test_hmac failed" & exit 1)
	@test_etm.exe || (echo "test_etm failed" & exit 1)
	@test_etm_file.exe || (echo "test_etm_file failed" & exit 1)
	@echo "All tests executed"

clean:
	rm -f src/*.o $(LIB) test_etm test_rng test_hmac test_etm_file aes_demo
