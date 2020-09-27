CC=gcc
CFLAGS=-g -Wall -Wextra -std=c89 -pedantic
INC_DIR=../../include/source
LOCAL_INCLUDES=$(INC_DIR)/hex_encoding.c $(INC_DIR)/crypto_utility.c $(INC_DIR)/arbitrary_precision.c $(INC_DIR)/diffie_hellman.c $(INC_DIR)/md4.c $(INC_DIR)/sha1.c $(INC_DIR)/aes.c
LIB=-lgmp

build: main.c
	$(CC) $(CFLAGS) $(LOCAL_INCLUDES) main.c -o main $(LIB)

ubsan: main.c
	$(CC) $(CFLAGS) $(LOCAL_INCLUDES) -fsanitize=undefined main.c -o main $(LIB)

asan: main.c
	$(CC) $(CFLAGS) $(LOCAL_INCLUDES) -fsanitize=address main.c -o main $(LIB)

run: main
	./main

clean: main
	rm -f main
