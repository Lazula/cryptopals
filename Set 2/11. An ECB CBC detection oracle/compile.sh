#!/bin/bash
cc -g main.c ../../include/source/base64.c ../../include/source/aes.c ../../include/source/crypto_utility.c -o main $@
