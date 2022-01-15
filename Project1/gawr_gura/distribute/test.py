from pwn import *
lib = ELF("/lib/x86_64-linux-gnu/libc.so.6")

print(b'a'*0x30)