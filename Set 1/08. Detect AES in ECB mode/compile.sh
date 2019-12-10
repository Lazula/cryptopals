#!/bin/bash
cc -g main.c ../../include/source/hex_encoding.c ../../include/source/aes.c -o main $@
