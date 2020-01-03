CC=cc
#-Wall -Wextra -std=c89 -pedantic to be added later
CFLAGS=-g

INC_DIR=../../include/source
LOCAL_INCLUDES=$(INC_DIR)/hex_encoding.c $(INC_DIR)/decrypt_single_byte_xor.c $(INC_DIR)/repeating_key_xor.c $(INC_DIR)/frequency_analysis.c

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
