---
title: "Stack unwinding and the story of a thief"
date: 2023-06-09T01:11:28+07:00
draft: false
description: "Some notes about stack unwinding and a short writeup for thiefcat"
---

# Table of Contents
1. [Intro](#intro)
2. [Stack Unwinding](#stack-unwinding)
3. [thiefcat](#thiefcat-3-solves)
    1. [Description](#description)
    2. [Get DWARF bytecode](#get-dwarf-bytecode)
    3. [Reversing](#reversing)
4. [References](#references)

# Intro
Two weeks ago, I played justCTF with r3kapig and we managed to get the first place. There's one reversing challenge that's really unique as it abuses the internal exception handling process to create an exotic VM. This blog is solely my brief note about how stack unwinding works in the exception handling procedure and a short writeup for that challenge.

# Stack Unwinding

Most of the time when a program encounters an unexpected behaviour (for example division by zero), it will be terminated. Exception handle was introduced to help programmers handle these behaviour by themselve and still preserve the original flow of the code.

In C++, they introduced keywords like `try`, `throw`, `catch` to handle exceptions. Let's look at the following code:

```C
void function_A(int a, int b) {
    try {
        if (b == 0) 
            throw 404;
        int c = a / b;
        puts("Success!!!");
    } catch(...) {
        puts("Error!!!");
    }

    puts("Finish executing!!!");
}
```

You can see that the line `int c = a / b;` may cause problem because `b` can be zero. The idea of those 3 keywords is that if there's an error happens in the `try` block, we can `throw` it and the `catch` block will handle the error for you. So if `b` is zero, `thow 404;` will be executed and the program will print `Error!!!` in the `catch` block. Let's move on to a little bit more complicated example:

```C
void function_C(int a, int b) {
    if (b == 0) 
        throw 404;
    int c = a / b;
    puts("Success!!!");
}

void function_B() {
    function_C(1, 0);
}

void function_A() {
    function_B();
}

int main() {
    try {
        function_A();
    } catch(...) {
        puts("Error!!!");
    }
}
```

This time the potential problematic code is in `function_C`, but this time the handling function is in `main()`. This is what it looks like in lower level:

![](https://hackmd.io/_uploads/rkCnUb_vn.png)

The way it works is that when an error is occur in `function_C`, first it will walk through all the previous stack frame in order to find the one that has a handler that accept to handle our current error. If we can't find any stack frame that can do so, the program will be terminated, otherwise we'll start from the current stack frame and walk through again, but this time it will cleanup memories in these stack frames until it counters the one that accept handling our error. This process is called stack unwinding.

The interesting part is that most of the time, C++ uses DWARF bytecode to implement stack unwinding process, and this bytecode is stored `.eh_frame` section. You can use `readelf` command to see the content of the instructions:

```sh
nguyenguyen753@nguyenguyen753:~/Desktop$ readelf --debug-dump=frames a.out 
Contents of the .eh_frame section:


00000000 0000000000000014 00000000 CIE
  Version:               1
  Augmentation:          "zR"
  Code alignment factor: 1
  Data alignment factor: -8
  Return address column: 16
  Augmentation data:     1b
  DW_CFA_def_cfa: r7 (rsp) ofs 8
  DW_CFA_offset: r16 (rip) at cfa-8
  DW_CFA_nop
  DW_CFA_nop

00000018 0000000000000014 0000001c FDE cie=00000000 pc=0000000000001100..0000000000001126
  DW_CFA_advance_loc: 4 to 0000000000001104
  DW_CFA_undefined: r16 (rip)
  DW_CFA_nop
  DW_CFA_nop
  DW_CFA_nop
  DW_CFA_nop

00000030 0000000000000024 00000034 FDE cie=00000000 pc=0000000000001020..0000000000001090
  DW_CFA_def_cfa_offset: 16
  DW_CFA_advance_loc: 6 to 0000000000001026
  DW_CFA_def_cfa_offset: 24
  DW_CFA_advance_loc: 10 to 0000000000001030
  DW_CFA_def_cfa_expression (DW_OP_breg7 (rsp): 8; DW_OP_breg16 (rip): 0; DW_OP_lit15; DW_OP_and; DW_OP_lit10; DW_OP_ge; DW_OP_lit3; DW_OP_shl; DW_OP_plus)
  DW_CFA_nop
  DW_CFA_nop
  DW_CFA_nop
  DW_CFA_nop
...
```

In general, `.eh_frame` will describe how we can find other stack frames in stack unwinding process. Another interesting thing about DWARF VM is that it is a stack-based VM, turing-complete and can access memories, registers in the program. With this in mind, back in the day people came up with an idea to write malicious codes in DWARF bytecode, hide it in `.eh_frame` to avoid being detected. You can look at [this video](https://www.youtube.com/watch?v=nLH7ytOTYto) to understand more about how they hide malicous code in DWARF format.

# thiefcat (3 solves)

Although hiding codes in `.eh_frame` is a really old techniques (the video was recorded in 2011), it still creates certain difficulties as there're no specific tools to analyze this type of bytecode and I personally didn't know about this technique until I encountered this challenge.

## Description

```
My friend told me they made a terminal based game, but using some issue with stock netcat as an excuse they sent me this netcat-like binary telling me to use it instead! I didn't get the source code, but I took a quick look at it using a well-known state-of-the-art reverse engineering tool and it seemed perfectly safe to run. However, it stole the flag for this task from me! Can you get it back?

I recorded the network traffic and reconstructed a simple server in Python from it. The program was confirmed to run in a ubuntu:20.04 container, but it should run on almost any Linux distro out there.
```

Given files: [thiefcat](https://github.com/MochiNishimiya/mochinishimiya.github.io/raw/main/challenges/jctf_2023/thiefcat), [thiefcat.py](https://github.com/MochiNishimiya/mochinishimiya.github.io/raw/main/challenges/jctf_2023/thiefcat.py)

## Get DWARF bytecode

The binary is really simple: `theifcat.py` acts as a server, `thiefcat` will connect to it, after that `flag.txt` (you have to create a new file) will be deleted and a random byte array will be printed by `thiefcat.py`. At this point I knew it was just a simple encryption challenge where we have to decrypt the encrypted flag to get it, but if you look at `thiefcat` closely, the code contains nothing related to any kind of encryption. Then one of my teammate find out about code is being hidden in `.eh_frame`:

![](https://hackmd.io/_uploads/Sy7g7D_wh.png)

After reading and learning about DWARF bytecode, I knew what I had to do next: Obtaining the real logic. Again, I used `readelf` to extract the code:

```sh
...
00000178 0000000000000030 0000008c FDE cie=000000f0 pc=0000000000001a11..0000000000001a12
  DW_CFA_val_expression: r7 (rsp) (DW_OP_reg7 (rsp); DW_OP_lit8; DW_OP_plus)
  DW_CFA_val_expression: r16 (rip) (DW_OP_reg0 (rax); DW_OP_const2u: 6144; DW_OP_plus)
  DW_CFA_val_expression: r6 (rbp) (DW_OP_reg7 (rsp); DW_OP_lit16; DW_OP_plus)
  DW_CFA_val_expression: r3 (rbx) (DW_OP_reg0 (rax); DW_OP_const2u: 5447; DW_OP_plus)
  DW_CFA_val_expression: r12 (r12) (DW_OP_reg12 (r12); DW_OP_lit1; DW_OP_plus)
  DW_CFA_nop

000001ac 0000000000000034 000000c0 FDE cie=000000f0 pc=0000000000001a12..0000000000001a13
  DW_CFA_val_expression: r7 (rsp) (DW_OP_reg7 (rsp); DW_OP_lit8; DW_OP_plus)
  DW_CFA_val_expression: r16 (rip) (DW_OP_reg0 (rax); DW_OP_const2u: 6144; DW_OP_plus)
  DW_CFA_val_expression: r6 (rbp) (DW_OP_reg7 (rsp); DW_OP_const1u: 136; DW_OP_plus)
  DW_CFA_val_expression: r3 (rbx) (DW_OP_reg7 (rsp); DW_OP_const1u: 32; DW_OP_plus; DW_OP_lit28; DW_OP_plus; DW_OP_deref)
  DW_CFA_val_expression: r12 (r12) (DW_OP_reg12 (r12); DW_OP_lit1; DW_OP_plus)
  DW_CFA_nop
  DW_CFA_nop

000001e4 0000000000000034 000000f8 FDE cie=000000f0 pc=0000000000001a13..0000000000001a14
  DW_CFA_val_expression: r7 (rsp) (DW_OP_reg7 (rsp); DW_OP_lit8; DW_OP_plus)
  DW_CFA_val_expression: r16 (rip) (DW_OP_reg0 (rax); DW_OP_const2u: 6144; DW_OP_plus)
  DW_CFA_val_expression: r6 (rbp) (DW_OP_reg0 (rax); DW_OP_const2u: 32824; DW_OP_plus; DW_OP_lit0; DW_OP_plus)
  DW_CFA_val_expression: r3 (rbx) (DW_OP_reg0 (rax); DW_OP_const2u: 5533; DW_OP_plus)
  DW_CFA_val_expression: r12 (r12) (DW_OP_reg12 (r12); DW_OP_lit1; DW_OP_plus)
  DW_CFA_nop
...
```

Unfortunately, there isn't any reference to DWARF bytecode on the internet, but luckily the [source code](https://codebrowser.dev/llvm/libunwind/src/DwarfInstructions.hpp.html) is clear enough to understand the functionality of each instructions. The bytecode from `readelf` isn't readable enough for me to reverse so I write a small script to print bytecode in nicer format:

```py
all = open('log.txt', 'r').read().split('\n')
cou = 0

def ins_decode(x):
    try:
        stack = []
        for ins in x:
            if 'DW_OP_reg' in ins:
                x = ins.split('(')[1].split(')')[0]
                if 'rax' in x:
                    x = 'BASE_ADDR'
                stack.append(x)
            elif 'DW_OP_const' in ins:
                stack.append(ins.split(': ')[1].strip())
            elif 'DW_OP_plus' in ins:
                x = stack[len(stack) - 1]
                stack.pop()
                stack[len(stack) - 1] = f'({stack[len(stack) - 1]} + {x})'
            elif 'DW_OP_mul' in ins:
                x = stack[len(stack) - 1]
                stack.pop()
                stack[len(stack) - 1] = f'({stack[len(stack) - 1]} * {x})'
            elif 'DW_OP_minus' in ins:
                x = stack[len(stack) - 1]
                stack.pop()
                stack[len(stack) - 1] = f'({stack[len(stack) - 1]} - {x})'
            elif 'DW_OP_mod' in ins:
                x = stack[len(stack) - 1]
                stack.pop()
                stack[len(stack) - 1] = f'({stack[len(stack) - 1]} % {x})'
            elif 'DW_OP_shl' in ins:
                x = stack[len(stack) - 1]
                stack.pop()
                stack[len(stack) - 1] = f'({stack[len(stack) - 1]} << {x})'
            elif 'DW_OP_shr' in ins:
                x = stack[len(stack) - 1]
                stack.pop()
                stack[len(stack) - 1] = f'({stack[len(stack) - 1]} >> {x})'
            elif 'DW_OP_lt' in ins:
                x = stack[len(stack) - 1]
                stack.pop()
                stack[len(stack) - 1] = f'({stack[len(stack) - 1]} < {x})'
            elif 'DW_OP_ge' in ins:
                x = stack[len(stack) - 1]
                stack.pop()
                stack[len(stack) - 1] = f'({stack[len(stack) - 1]} >= {x})'
            elif 'DW_OP_xor' in ins:
                x = stack[len(stack) - 1]
                stack.pop()
                stack[len(stack) - 1] = f'({stack[len(stack) - 1]} ^ {x})'
            elif 'DW_OP_or' in ins:
                x = stack[len(stack) - 1]
                stack.pop()
                stack[len(stack) - 1] = f'({stack[len(stack) - 1]} | {x})'
            elif 'DW_OP_and' in ins:
                x = stack[len(stack) - 1]
                stack.pop()
                stack[len(stack) - 1] = f'({stack[len(stack) - 1]} & {x})'
            elif 'DW_OP_not' in ins:
                stack[len(stack) - 1] = f'(~{stack[len(stack) - 1]})'
            elif 'DW_OP_neg' in ins:
                stack[len(stack) - 1] = f'(-{stack[len(stack) - 1]})'
            elif 'DW_OP_ne' in ins:
                x = stack[len(stack) - 1]
                stack.pop()
                stack[len(stack) - 1] = f'({stack[len(stack) - 1]} != {x})'
            elif 'DW_OP_eq' in ins:
                x = stack[len(stack) - 1]
                stack.pop()
                stack[len(stack) - 1] = f'({stack[len(stack) - 1]} == {x})'
            elif 'DW_OP_deref' in ins:
                if 'DW_OP_deref_size' in ins:
                    size = ins.split(': ')[1].strip()
                    if size == '1':
                        stack[len(stack) - 1] = f'[{stack[len(stack) - 1]}].byte_size'
                    elif size == '2':
                        stack[len(stack) - 1] = f'[{stack[len(stack) - 1]}].word_size'
                    elif size == '4':
                        stack[len(stack) - 1] = f'[{stack[len(stack) - 1]}].dword_size'
                else:
                    stack[len(stack) - 1] = f'[{stack[len(stack) - 1]}].qword_size'
            elif 'DW_OP_lit' in ins:
                val = ins.split('DW_OP_lit')[1].strip()
                stack.append(val)
            else:
                print(f'unknown: {ins}')
                exit(0)
        return stack[len(stack) - 1]
    except:
        print(stack)
        exit(-1)

for x in all:
    if 'FDE' in x:
        print()
        print(f'ins_block_{hex(cou)[2:]}')
        cou += 1
    elif 'DW_CFA_val_expression' not in x.strip():
        continue
    elif 'rip' in x:
        continue
    elif 'DW_CFA_nop' in x:
        continue
    else:
        x = x.split('DW_CFA_val_expression: ')[1]
        x = x[x.find(' '):].strip()
        val = x[:x.find(' ')]
        x = x[x.find(' '):].strip()
        x = x[1:-1].split('; ')
        print(f'{val[1:-1]} = {ins_decode(x)}')
```

The code after formatting looks readable enough to analyze:

```
ins_block_0
rsp = (rsp + 8)
rbp = (rsp + 16)
rbx = (BASE_ADDR + 5447)
r12 = (r12 + 1)

ins_block_1
rsp = (rsp + 8)
rbp = (rsp + 136)
rbx = [((rsp + 32) + 28)].qword_size
r12 = (r12 + 1)

ins_block_2
rsp = (rsp + 8)
rbp = ((BASE_ADDR + 32824) + 0)
rbx = (BASE_ADDR + 5533)
r12 = (r12 + 1)
...
```

## Reversing

The basic implementation behind this code is that it'll set values for two registers `rbx` and `rsp` in each exception handling process, and the `catch` block will set memory at `rbp` to `rbx` by following code:

```sh
.text:00000000000019F8 ;   catch(std::exception) // owned by 17B5
.text:00000000000019F8                 mov     [rbp+var_s0], rbx
.text:00000000000019FC                 mov     rax, [rsp+8]
.text:0000000000001A01                 mov     [rsp+4470h+var_4470], rax
.text:0000000000001A05                 mov     rbp, rsp
.text:0000000000001A08                 leave
.text:0000000000001A09                 retn
```

There're some small details worth noticing while reversing this code:
  - `r12` acts as pc in the VM, as you can see almost every func will end with `r12 = (r12 + 1)` with some exceptions that it will set `r12` to a specific value, which indicates it's a jump or a call instruction.
  - The VM implemented its own stack frame, which will store return address and arguments that's being passed to a function. 

Static analyzing is not enough cause we have to observe how memories being modified to have a better understanding of the algorithm, at the same time debug it would be too hard since we have to dig down into libraries that implement this type of bytecode, which is really time consuming. There's an easy approach which I used while doing this is to put breakpoint at 2 places: `0x159D` and `0x19F8`. Putting breakpoint at `0x159D` to observe memories before executing the VM and at `0x19F8` to observe the result after executing a block of instructions.

The flow should look like this:
  - `ins_block_0` to `ins_block_2f`: it'll try to find address of `open`, `exit` and `unlink` functions in `libc.so.6`.
  - `ins_block_30` to `ins_block_36`: it'll look for `Session ID:` string in the received message from server. The program will exit if the string can't be found.
  - `ins_block_39` to `ins_block_50`: Open `flag.txt`, read and then unlink the file. You may notice that `read` function isn't being imported, it actually uses `read` from the binary itself since the binary has to use `read` to receive replied message over socket.
  - And the rest is about encrypting the flag.

All opeartions that encrypt the flag can be found at `ins_block_ad` and `ins_block_ae`:

```
ins_block_ad
rbp = ([(rsp + 128)].qword_size + 8)
rbx = (((([([(rsp + 128)].qword_size + 8)].qword_size >> 8) | ([([(rsp + 128)].qword_size + 8)].qword_size << 56)) + [([(rsp + 128)].qword_size + 16)].qword_size) ^ [([([(rsp + 128)].qword_size + 24)].qword_size + ((4 ^ [([(rsp + 128)].qword_size + 0)].qword_size) << 3))].qword_size)
r12 = (r12 + 1)

ins_block_ae
rbp = ([(rsp + 128)].qword_size + 16)
rbx = ((([([(rsp + 128)].qword_size + 16)].qword_size << 3) | ([([(rsp + 128)].qword_size + 16)].qword_size >> 61)) ^ [([(rsp + 128)].qword_size + 8)].qword_size)
r12 = (r12 + 1)
```

After understanding the algorithm, I implemented the encryption part in python:

```py
from pwn import *
key = bytes.fromhex('3644607d4311ecda06c054893ea63302d51611e49ec895a2457b376e6f95e69c3ae13d773a755a62a36eab01cb4d0c6a17c63817f743e78a7119957f9cd6fbc01ca7f358862c4d89653a05792ca4b2514701ea5f8f5e5b5f28cfd1b375d9f437a029905d0fcc64f5fa0ad2ec6dee897d9c09426593ee2f971197554baa3bd45f76641a26ab3b1babf638442fcb2ba9ffb41742bb98c219be32c613a7f007933128f80ee4865acc45a6499cc7dc7af7d10e78668f6dc64c39253c2a60128e65b814b714df5ce1fbcfd544575608b2d7766011bcf7832a5d5f8e9ce104215faed1cf799664245fabd00fda69b4e9c1530f4564b4dd6fc443fac97c90ed4581dae548561344c74fc6e29e54a10c371ca0fc5134c77c214f8a334ba3d8f3dba03246329e2b5d6a079838027db3fb3e2f6164bb845dbaa4a908dbde6e29df50e6455c')
li = []
for i in range(0, len(key), 8):
    li.append(u64(key[i:i+8]))

MOD64 = 0xffffffffffffffff

inp = b'M' * 32
x = u64(inp[:8])
y = u64(inp[8:16])
u = u64(inp[16:24])
v = u64(inp[24:32])

for i in range(40):
    x = ((x >> 8) + (x << 56)) + y
    x ^= li[i ^ 4]
    x &= MOD64
    y = (((y >> 61) + (y << 3)) ^ x) & MOD64

u ^= x
v ^= y
ans = p64(x) + p64(y)
x, y = u, v

for i in range(40):
    z = ((x >> 8) + (x << 56)) + y
    z ^= li[i ^ 4]
    z &= MOD64
    x = z
    y = (((y >> 61) + (y << 3)) ^ x) & MOD64

ans += p64(x) + p64(y)
print(ans)
```

And create a solve script:

```py
from pwn import *
key = bytes.fromhex('3644607d4311ecda06c054893ea63302d51611e49ec895a2457b376e6f95e69c3ae13d773a755a62a36eab01cb4d0c6a17c63817f743e78a7119957f9cd6fbc01ca7f358862c4d89653a05792ca4b2514701ea5f8f5e5b5f28cfd1b375d9f437a029905d0fcc64f5fa0ad2ec6dee897d9c09426593ee2f971197554baa3bd45f76641a26ab3b1babf638442fcb2ba9ffb41742bb98c219be32c613a7f007933128f80ee4865acc45a6499cc7dc7af7d10e78668f6dc64c39253c2a60128e65b814b714df5ce1fbcfd544575608b2d7766011bcf7832a5d5f8e9ce104215faed1cf799664245fabd00fda69b4e9c1530f4564b4dd6fc443fac97c90ed4581dae548561344c74fc6e29e54a10c371ca0fc5134c77c214f8a334ba3d8f3dba03246329e2b5d6a079838027db3fb3e2f6164bb845dbaa4a908dbde6e29df50e6455c')
li = []
for i in range(0, len(key), 8):
    li.append(u64(key[i:i+8]))

MOD64 = 0xffffffffffffffff

u = 0
v = 0

def reverse(x, y):
    for i in range(39, -1, -1):
        y ^= x
        y = ((y << 61) + (y >> 3)) & MOD64
        x ^= li[i ^ 4]
        x -= y
        x &= MOD64
        x = ((x << 8) + (x >> 56)) & MOD64
    return x, y

k = b'K\xb9\xa5\x19\x9b\x18y\xdc\xad\xb0\x112I\x01\tJ\xed\xa7N\x0c\x95{\x0b$\x97J\xb0\\p\n\xf5\xaf'

x0 = u64(k[0:8])
y0 = u64(k[8:16])
x, y = reverse(x0, y0)
ans = bytes.fromhex(hex(x)[2:])[::-1] + bytes.fromhex(hex(y)[2:])[::-1]

x = u64(k[16:24])
y = u64(k[24:32])
x, y = reverse(x, y)
ans += bytes.fromhex(hex(x ^ x0)[2:])[::-1] + bytes.fromhex(hex(y ^ y0)[2:])[::-1]
print(ans)
```

`justCTF{iM_5c4r3d_oF_7hIs_c4T!}`

I learned so much about exception handling after this CTF and it also gives me a similar vibe from a google CTF challenge named `eldar` (which is also abusing internal linux code to create an exotic VM). Big thanks to `ptrtofuture#4398` for creating this challenge.

# References:
  - https://www.youtube.com/watch?v=nLH7ytOTYto
  - https://refspecs.linuxfoundation.org/abi-eh-1.22.html
  - https://codebrowser.dev/llvm/libunwind/src/DwarfInstructions.hpp.html