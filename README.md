## cryptopals solutions

This repository contains my solutions to the challenges at cryptopals.com, organized by set.

Each challenge uses a `main.c` file, compiled with `make`, which automatically adds includes files and provides debugging information with gcc's `-g` option. A pre-compiled ELF binary is included as well. Use `make asan` to compile with ASan or `make ubsan` to compile with UBSan. Run `python3 build_all.py` to automatically run `make` for all challenges if the included binaries do not work (due to different operating system, etc.).

The `include` directory is a collection of header and source files containing helper functions that are used in multiple places, such as encoder/decoder functions and ciphers.

Tools used:
* tmux - Session management
* vim - All text file editing
* gcc - Compiling and adding debug information
* gdb - Debugging, instruction stepping, memory examination
* asan - gcc flag -fsanitize=address displays memory overread/overwrite and memory leaks

## endianness
`include/local_endian.h` is present to make endian-dependent code portable. By default, it will compile with little-endian support enabled. A simple preprocessor directive can be edited in the source to switch between little- and big-endian modes. Unfortunately, this could not be done automatically while adhering strictly to the C Standard, as it leaves all concerns of endianness implementation-defined (in fact, the C89 standard does not contain any references to endianness). Word-based endianness (e.g PDP, Honeywell) is not supported.

## warnings
The code here should absolutely not be used for serious encryption - it's a series of challenges about the *weaknesses* of these methods, after all.

As far as application security, while I try to maintain a basic level of security in all my programs, these are a bit loose since they aren't really "programs" proper. What I'm trying to say is that you probably shouldn't put a suid bit on these.

Machines where CHAR\_BIT != 8 have not been considered. Some things have been made to refuse compilation because they are almost certain to fail, but others may simply silently fail to do as intended. Basically, CHAR\_BIT != 8 is undefined for this project.

## license
All code in this project for which I have the authority to do so is released into the public domain via the Unlicense (see LICENSE). I don't own glibc or any of the tools used.
