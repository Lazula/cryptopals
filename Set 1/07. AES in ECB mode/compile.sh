#!/bin/bash
cc -g main.c ../../include/source/base64.c ../../include/source/aes.c ../../include/source/repeating_key_xor.c -o main $@
