CC=gcc
CFLAGS=-g -Wall -Wextra -std=c89 -pedantic -I../../include
INC_DIR=../../include/source
LOCAL_INCLUDES=$(INC_DIR)/hex_encoding.c $(INC_DIR)/crypto_utility.c $(INC_DIR)/arbitrary_precision.c $(INC_DIR)/diffie_hellman.c $(INC_DIR)/sha256.c $(INC_DIR)/apnum_sha256.c $(INC_DIR)/srp.c
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
