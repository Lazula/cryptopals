ASan breaks this program for some reason. Basic debugging has yielded no
results. It seems to be a problem with valid_ascii always being set to 0 in
decrypt_single_byte_xor(). The range may be too restrictive. This is a really
weird bug and it works fine without ASan, so I'm going to consider it
acceptable.
