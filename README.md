## cryptopals solutions

This repository contains my solutions to the challenges at cryptopals.com, organized by set.

Each challenge uses a `main.c` file, compiled with `make`, which automatically adds includes files and provides debugging information with gcc's `-g` option. Use `make asan` to compile with ASan or `make ubsan` to compile with UBSan. Run `python3 build_all.py` to automatically run `make` for all challenges.

The `include` directory is a collection of header and source files containing helper functions that are used in multiple places, such as encoder/decoder functions and ciphers.

Tools used:
* tmux - Session management
* vim - All text file editing
* gcc - Compiling and adding debug information
* gdb - Debugging, instruction stepping, memory examination
* asan - gcc flag -fsanitize=address displays memory overread/overwrite and memory leaks

## setting up GMP

Beginning with Set 5, bignums are needed. GMP is used to provide support for these large numbers. Download GMP 6.2.0 from `https://ftp.gnu.org/gnu/gmp/`, and install it with the standard `./configure`, `make`, (optionally, `make check` to run self-tests) and `make install`. Compatibility with other GMP versions cannot be guaranteed.

## endianness
`include/local_endian.h` is present to make endian-dependent code portable. By default, it will compile with little-endian support enabled. A simple preprocessor directive can be edited in the source to switch between little- and big-endian modes. Unfortunately, this could not be done automatically while adhering strictly to the C Standard, as it leaves all concerns of endianness implementation-defined (in fact, the C89 standard does not contain any references to endianness). PDP and Honeywell endian are not supported.

## warnings
The code here should absolutely not be used for serious encryption - it's a series of challenges about the *weaknesses* of these methods, after all.

As far as application security, while I try to maintain a basic level of security in all my programs, these are a bit loose since they aren't really "programs" proper. What I'm trying to say is that you probably shouldn't put a suid bit on these.

Machines where CHAR\_BIT != 8 have not been considered. Some things have been made to refuse compilation because they are almost certain to fail, but others may simply silently fail to do as intended. Consider CHAR\_BIT != 8 undefined for this project.

## license
All code in this project for which I have the authority to do so is released into the public domain via the Unlicense (see LICENSE). I don't own glibc or any of the tools used.

GMP is distributed under the GNU LGPLv3 license.
