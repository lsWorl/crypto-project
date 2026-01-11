CC=gcc
CFLAGS=-Iinclude -Wall -Wextra -g
SRCS=$(wildcard src/*.c)
OBJS=$(SRCS:.c=.o)
LIB=libcrypto.a

.PHONY: all clean test

all: $(LIB)

$(LIB): $(OBJS)
	ar rcs $@ $^

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

test: $(LIB)
	$(CC) $(CFLAGS) -o test_etm test/test_etm.c $(LIB) -lbcrypt
	$(CC) $(CFLAGS) -o test_rng test/test_rng.c $(LIB) -lbcrypt
	$(CC) $(CFLAGS) -o aes_demo AES/AESEncryption.c AES/AESDecryption.c AES/common.c AES/main.c $(LIB) -lbcrypt
	@echo "Built test_etm, test_rng and aes_demo"

clean:
	rm -f src/*.o $(LIB) test_etm test_rng
