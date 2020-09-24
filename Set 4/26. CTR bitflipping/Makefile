CC=gcc
CFLAGS=-g -Wall -Wextra -std=c89 -pedantic
INC_DIR=../../include/source
LOCAL_INCLUDES=$(INC_DIR)/aes.c $(INC_DIR)/crypto_utility.c

build: main.c
	$(CC) $(CFLAGS) $(LOCAL_INCLUDES) main.c -o main

ubsan: main.c
	$(CC) $(CFLAGS) $(LOCAL_INCLUDES) -fsanitize=undefined main.c -o main

asan: main.c
	$(CC) $(CFLAGS) $(LOCAL_INCLUDES) -fsanitize=address main.c -o main

run: main
	./main

clean: main
	rm -f main
