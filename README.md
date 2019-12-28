## cryptopals solutions

This repository contains my solutions to the challenges at cryptopals.com, organized by set.

Each challenge uses a **main.c** file, compiled with **compile.sh**, a simple bash line which adds the source files for the local includes and adds debugging information with gcc's **-g** option. A pre-compiled binary is included as well.

The **include** directory is a collection of header and source files containing helper methods that are used in multiple places, such as encoder/decoder functions and ciphers.

While I try to maintain a basic level of security in all my programs, these are a bit loose since they aren't really "programs" proper. What I'm trying to say is that you probably shouldn't put a suid bit on these.

Signed chars are used for ASCII text (null-terminated strings). Unsigned chars are used whenever binary safety is needed.

Tools used:
* tmux - Session management
* vim - All text file editing
* gcc - Compiling and inserting automatic 0xcc debug traps with asm("int3");
* gdb - Debugging, memory examination
* asan, valgrind - Memory usage debugging with valgrind flags --leak-check=yes and --track-origins=yes and gcc flag -fsanitize=address
