#!/bin/bash
cc -g main.c ../../include/source/hex_encoding.c ../../include/source/decrypt_single_byte_xor.c ../../include/source/repeating_key_xor.c ../../include/source/frequency_analysis.c -o main $@
