---
title: "CorCTF 2022"
date: 2022-08-05T01:11:28+07:00
draft: false
description: "This week I spent a little time playing CorCTF, and I managed to solve two challenges which are really interesting. So this writeup is going to be my solution for those two."
---

# Table of Contents
1. [Hackermans Dungeon](#hackermans-dungeon-8-solves)
    1. [Reversing](#reversing)
    2. [Obtaining the flag](#obtaining-the-flag)
2. [Bogus](#bogus-6-solves)
    1. [VPERMD](#vpermd)
    2. [VPUNPCKLDQ](#vpunpckldq)
    3. [VPUNPCKHDQ](#vpunpckhdq)
    4. [VPCMPGTD](#vpcmpgtd)
    5. [Putting it all together](#putting-it-all-together)
    6. [Solution](#solution)

# Hackermans Dungeon (8 solves)

`Hackerman told us he cannot be hacked. Can you hack hackerman?`

It's a normal AMD64 PE file with the purpose of checking user's username and password.

![hackermansdungeon](https://i.imgur.com/x8QeyXs.png)

Loading it into IDA and messing around, we can spot some functions that look similar to this:

```c
...
v28 = v25 + __ROL4__(v21 + (v25 & v20 | v26) + v18 - 40341101, 12);
v29 = v28 + __ROR4__(v22 + (v25 & v28 | v20 & ~v28) + v24, 15);
v30 = v29 + __ROR4__(v27 + (v29 & v28 | v25 & ~v29) + 1236535329 + v20, 10);
v31 = v30 + __ROL4__(a2[1] - 165796510 + (v30 & v28 | v29 & ~v28) + v25, 5);
v32 = v31 + __ROL4__(v28 + v83 - 1069501632 + (v30 & ~v29 | v31 & v29), 9);
v33 = v32 + __ROL4__(v84 + (v30 & v32 | v31 & ~v30) + v29 + 643717713, 14);
v34 = v33 + __ROR4__(*a2 + (v31 & v33 | v32 & ~v31) + v30 - 373897302, 12);
v35 = v34 + __ROL4__(v85 + (v34 & v32 | v33 & ~v32) + v31 - 701558691, 5);
v36 = v35 + __ROL4__(v12 + (v35 & v33 | v34 & ~v33) + v32 + 38016083, 9);
v37 = v36 + __ROL4__(v27 + (v34 & v36 | v35 & ~v34) + v33 - 660478335, 14);
v38 = v37 + __ROR4__(v88 + (v35 & v37 | v36 & ~v35) + v34 - 405537848, 12);
v39 = v38 + __ROL4__(v79 + (v38 & v36 | v37 & ~v36) + v35 + 568446438, 5);
v40 = v39 + __ROL4__(v22 + (v39 & v37 | v38 & ~v37) + v36 - 1019803690, 9);
v41 = v40 + __ROL4__(v37 + v87 + (v38 & v40 | v39 & ~v38) - 187363961, 14);
v42 = v41 + __ROR4__(v80 + (v39 & v41 | v40 & ~v39) + v38 + 1163531501, 12);
v43 = v42 + __ROL4__(v21 + (v42 & v40 | v41 & ~v40) + v39 - 1444681467, 5);
...
```

If you have reversed enough binaries, you would find it similar to some pieces of code that comes from a well known encryption algorithm. To test my theory, I used [findcrypt-yara](https://github.com/polymorf/findcrypt-yara) plugin from IDA to find if there's any well known constant in an algorithm. And it ended up showing 3 popular ones: `CRC32`, `SHA256` and `MD5`.

Having those hints, I can easily spot functions that are related to those 3 algorithms:

```c
...
v29 = 0i64;
v30 = 1732584193;
v20 = -1i64;
v31 = -271733879;
v32 = -1732584194;
v33 = 271733878;
do
++v20;
while ( Src[v20] );
MD5_Init(&v29, Src);
MD5_Final(&v29);
*(_OWORD *)&v28[1] = v34;
do
++v9;
while ( Src[v9] );
SHA256(Src, v9);
if ( !strcmp(Buffer, "CORnwallis") && !memcmp(&unk_7FF7EEF27068, Buf2, 0x20ui64) )
{
memset(v35, 0, sizeof(v35));
CHACHA_Init(v35, Buf2, &v28[1]);
LODWORD(v35[22]) = 42;
v35[15] = 42i64;
v22 = LOBYTE(v35[13]) | ((BYTE1(v35[13]) | (WORD1(v35[13]) << 8)) << 8);
v35[8] = 64i64;
HIDWORD(v35[22]) = LOBYTE(v35[13]) | ((BYTE1(v35[13]) | (WORD1(v35[13]) << 8)) << 8);
v23 = 0i64;
v24 = 64i64;
do
{
    if ( v24 >= 0x40 )
    {
    CHACHA_key_generate(v35);
    v8 = 0i64;
    v35[8] = 0i64;
    }
    v25 = *((_BYTE *)v35 + v8++);
    byte_7FF7EEF27040[v23] ^= v25;
    v24 = v8;
    ++v23;
    v35[8] = v8;
}
while ( v23 < 0x23 );
LODWORD(v28[0]) = 0;
CRC32(v22, v21, v28);
...
```

There is actually one exception that `findcrypt-yara` can't figure out, which is `CHACHA`. But we can easily identify that by finding the string `expand 32-byte k` in a function and google it, which results in many aritcles about `CHACHA`.

Eventually these valuable information will make our reversing life much more easier.

## Reversing

The program is pretty simple: it will compare our username with string `CORnwallis`, then it generates `SHA256` and `MD5` from our password for `key` and `nonce`, respectively, and use them for `CHACHA` to decrypt the flag. Finally the file will validate the decrypted flag by using `CRC32` and compare with a hardcoded value.

I made a python version of the program so that readers can visualize the flow of the binary easier:

```python
from pwn import *
import binascii

# password != flag, find one of those two and we can get the flag

def encrypt(password):
    for i in range(len(password)):
        v19 = (i + 1) % len(password)
        password[i] += 1
        password[i] = (~((password[v19] ^ password[i]) + 0x62)) & 0xff

    return b''.join(bytes([i]) for i in password)

def chacha20_key_generate(key, iv):
    def rotate(v, c):
        return ((v << c) & 0xffffffff) | v >> (32 - c)

    def quarter_round(x, a, b, c, d):
        x[a] = (x[a] + x[b]) & 0xffffffff
        x[d] = rotate(x[d] ^ x[a], 16)
        x[c] = (x[c] + x[d]) & 0xffffffff
        x[b] = rotate(x[b] ^ x[c], 12)
        x[a] = (x[a] + x[b]) & 0xffffffff
        x[d] = rotate(x[d] ^ x[a], 8)
        x[c] = (x[c] + x[d]) & 0xffffffff
        x[b] = rotate(x[b] ^ x[c], 7)

    init_state = list(b'expand 32-byte k' + key + p32(0x2a))
    for i in range(len(iv)):
        init_state.append(iv[i])
    ctx = [0] * 16

    for i in range(16):
        ctx[i] = (init_state[i * 4 + 3] << 24) + (init_state[i * 4 + 2] << 16) + (init_state[i * 4 + 1] << 8) + (init_state[i * 4])
    x = [i for i in ctx]

    for i in range(10):
        quarter_round(x, 0, 4,  8, 12)
        quarter_round(x, 1, 5,  9, 13)
        quarter_round(x, 2, 6, 10, 14)
        quarter_round(x, 3, 7, 11, 15)
        quarter_round(x, 0, 5, 10, 15)
        quarter_round(x, 1, 6, 11, 12)
        quarter_round(x, 2, 7,  8, 13)
        quarter_round(x, 3, 4,  9, 14)

    final_state = []
    for i in range(16):
        ctx[i] = (ctx[i] + x[i]) & 0xffffffff
        final_state.append(ctx[i] & 0xff)
        final_state.append((ctx[i] >> 8) & 0xff)
        final_state.append((ctx[i] >> 16) & 0xff)
        final_state.append((ctx[i] >> 24) & 0xff)
    return final_state


def chacha20_decrypt(data, key, iv=None, position=0):
    state = chacha20_key_generate(key, iv)
    li = list(data)
    for i in range(len(data)):
        li[i] ^= state[i]
    return li

# --------- Modify this ------------
iv = bytes.fromhex('dbfe4eaab5c3a69748367be5') # md5(encrypt(password))[:12]
# ----------------------------------

key = bytes.fromhex('9c00f1ac636216e2342f64ae3b82e3c02749a69c35df8c03554d55c101869d47') # sha256(encrypt(password))
ciphertext = bytes.fromhex('3aab3581d55f56b0cee5f5164db38d2d7823d01c00c1ec07190232914ab463ccedd908')

flag = chacha20_decrypt(ciphertext, key, iv)

assert flag == b'corctf{' and binascii.crc32(flag) == 0x5E5C4A02
```

Probably you saw those comments. Yes, we do have `SHA256` since it's already provided in challenge's binary, but we don't have `MD5` one. At this point we have to think of many options to crack this piece of code and get the flag.

## Obtaining the flag

There's one small note on the code above is that the author did a small change in our `CHACHA` algorithm, which he modified the `counter` value in initial key state from `0` to `0x2a` (For more information about `CHACHA`, you can check this [link](https://cr.yp.to/chacha/chacha-20080120.pdf)), that's the reason why I have to rewrite `CHACHA`'s whole implementation again. But interestingly, this small change made me spent almost a day learning this algorithm carefully because I thought that this may results to some vulnerability and we could get the flag from this.

I was wrong, but still worth a try.

I also came up with some crazy ideas like converting `SHA256` to `MD5` without knowing the plaintext, or maybe there're some OTP problems...

But everything leads to one thing: It's almost impossible to crack this code while the contest was still up.

I really frustrated at that point, but small idea came up to my mind: Maybe the password is weak!?

It's actually a legit way of attacking because everything related to crypto at that moment was impossible to solve or crack. So probably there would be an actual chance that the only way to solve this problem was hoping the password is acutally weak.

I downloaded `rockyou.txt` and started bruteforcing with this script:

```python
password = list(b'CORnwallis')

import hashlib

def encrypt(password):
    for i in range(len(password)):
        v19 = (i + 1) % len(password)
        password[i] += 1
        password[i] = (~((password[v19] ^ password[i]) + 0x62)) & 0xff

    return b''.join(bytes([i]) for i in password)

leak = open("rockyou.txt", "rb").readlines()

for i in leak:
    password = i.strip()

    print(password)

    sha256 = hashlib.sha256()
    password = encrypt(list(password))
    sha256.update(password)

    if sha256.digest() == bytes.fromhex('9c00f1ac636216e2342f64ae3b82e3c02749a69c35df8c03554d55c101869d47'):
        print('Found')
        break
```

And there is actually a result!! The password is `canthackmehackers`.

After getting the password, I reran the program with a debugger and checked the memory region that contains the flag after it decrypted:

![](https://i.imgur.com/7gTW3Uw.png)

`corctf{d1d_y0u_h4ck_m3_h4ck3rm4n?}`

----------------------------------

# Bogus (6 solves)

`It's taking so long...`

A simple flag checker challenge, but like the description said, the algorithm that checks the flag may take a while to finish, so probably the best thing to do at first is to understand the binary itself. 

Although many instructions have been documented, I'll try to explain some of it as simple as possible so we can visualize the flow of the algorithm easier.

And to make the explaination clearer, I'll assume that all `ymm` register is an array with size of 8 bytes.

## VPERMD

`vpermd  ymm0, ymm1, ymm2`

It'll swap `ymm2` values base on `ymm1` and put the result into `ymm0`:

![](https://i.imgur.com/OH2W1At.png)

And here's the python implementation:

```python
def swappos(source, pos):
    li = list(source)
    for i in range(len(pos)):
        li[i] = source[pos[i]]
    return li
```

## VPUNPCKLDQ

`vpunpckldq ymm2, ymm1, ymm0`

It'll take values in some specific positions from `ymm0`, `ymm1`, merge them and put the result in `ymm2`

![](https://i.imgur.com/JEyeHlx.png)

```python
def mergelow(source0, source1):
    li = []
    for i in range(2):
        li.append(source1[i])
        li.append(source0[i])
    for i in range(4, 6):
        li.append(source1[i])
        li.append(source0[i])
    return li
```

## VPUNPCKHDQ

`vpunpckhdq ymm2, ymm1, ymm0`

Similar to `vpunpckldq`, but it'll take the other positions to merge.

![](https://i.imgur.com/fm7Oeu8.png)

```python
def mergehigh(source0, source1):
    li = []
    for i in range(2, 4):
        li.append(source1[i])
        li.append(source0[i])
    for i in range(6, 8):
        li.append(source1[i])
        li.append(source0[i])
    return li
```

## VPCMPGTD

`vpcmpgtd ymm0, ymm1, ymm2`

It'll compare `ymm1` with `ymm2` at each positions. If `ymm1[i] > ymm2[i]` then `ymm0[i] = 0xf`, otherwise `ymm0[i] = 0`

![](https://i.imgur.com/3A5DjC7.png)

The implementation in python is a little bit different. Instead returning an array `ymm0`, I try to display the result as an int for further purposes.

```python
def compare_greater(source0, source1):
    res = 0
    for i in range(len(source0)):
        if source0[i] > source1[i]:
            res += (0xf << (4 * i))
    return res
```

## Putting it all together

Let's look at the challenge binary in IDA:

![](https://i.imgur.com/8Zcm1t2.png)

First it'll store an array of hardcoded values from `.rodata` to the stack. Then it'll read our input, a small note is that our input is 16 bytes long.

![](https://i.imgur.com/579Z6C4.png)

After that it'll check if our input is in range from A to P. If fail, it'll jump to an infinite loop and we can't escape from it. Else it will continue the validating process.

![](https://i.imgur.com/L7HrtGS.png)

Next it'll load our input into register `ymm0` and `ymm1`, each register holds 8 bytes of our input. It'll also load some constants `shift`, `shift2`, `msk` to registers.

![](https://i.imgur.com/ZjxprxE.png)

![](https://i.imgur.com/ee2rkbN.png)

This is the main logic of the entire binary. These codes is similar to this python script:

```python
...
r8 += 1
r11 = old_r11
r11 = (r11 * some_const + 1) & 0xffffffffffffffff
old_r11 = r11

id = (((r11 & 0xffff) << 5) // 4)
ymm6 = li[id:id+8]
r11 >>= 0x16
id = (((r11 & 0xffff) << 5) // 4)
ymm7 = li[id:id + 8]
r11 >>= 0x16
id = (((r11 & 0xffff) << 5) // 4)
ymm10 = li[id:id + 8]
r11 >>= 0x16
id = (((r11 & 0xffff) << 5) // 4)
ymm11 = li[id:id + 8]

ymm0 = swappos(ymm0, ymm6)
ymm1 = swappos(ymm1, ymm7)

ymm2 = mergelow(ymm0, ymm1)
ymm3 = mergehigh(ymm0, ymm1)

ymm4 = swappos(ymm2, ymm10)
ymm5 = swappos(ymm3, ymm11)

ymm0 = mergelow(ymm4, ymm5)
ymm1 = mergehigh(ymm4, ymm5)

ymm6 = swappos(ymm0, ymm12)

res = compare_greater(ymm0, ymm6)

if res >= 0xfffffff0:
    ymm6 = swappos(ymm1, ymm12)
    ymm3 = swappos(ymm0, ymm14)
    ymm6[0] = ymm3[0]
    res = compare_greater(ymm1, ymm6)
    if res == 0xffffffff:
        if r8 == 0x3B9ACA00:
            print('Found')
        else:
            print('No')
        exit(0)
...
```

Basically it will loop a couple of times with counter `r8d` and swap our input's positions. 

Finally it'll check `ymm0` and `ymm1` through some conditions. If it's true, it'll check if `r8d == 0x3B9ACA00`, if yes then our input is the flag.

After carefully analyzing the conditions, I know that `ymm0` and `ymm1` have to be `[0, 1, 2, 3, 4, 5, 6, 7]` and `[8, 9, 10, 11, 12, 13, 14, 15]` respectively to pass that check. At this point we can sum up the algorithm: We'll input a 16-bytes string, the binary will swap our input in a loop and at `0x3B9ACA00`th loop, our input has to be `ABCDEFGHIJKLMNOP`.

For more context, this algorithm is actually [bogosort](https://www.geeksforgeeks.org/bogosort-permutation-sort/)

## Solution

To solve this problem, I'll input string `ABCDEFGHIJKLMNOP` and see what's the state of `ymm0` and `ymm1` in `0x3B9ACA00`th loop, extract that state and rearrange the input to suit the condition. One of the way I do to obtain that final state is to patch the binary like this:

Before:

![](https://i.imgur.com/j1CX92U.png)

After:

![](https://i.imgur.com/Hn6hvPw.png)

We will attach a debugger to it, put breakpoint at `0x12ca` and run the binary. We'll obtain the final state in a short time.

Then all we have to do is just rearrange our input so that it fits the condition:

```python
li = [int(i) for i in '0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15'.split(' ')]
print(li)

final_state = bytes.fromhex('02 00 00 00 0D 00 00 00 06 00 00 00 08 00 00 00 05 00 00 00 04 00 00 00 0C 00 00 00 0B 00 00 00 09 00 00 00 0E 00 00 00 01 00 00 00 00 00 00 00 07 00 00 00 0A 00 00 00 0F 00 00 00 03 00 00 00')
order = []
for i in range(len(final_state) // 4):
    order.append(u32(final_state[i*4:(i+1)*4]))

print(order)
new_li = [0] * 16

for i in range(len(order)):
    new_li[order[i]] = li[i]

for i in new_li:
    print(chr(i + ord('A')), end = '')
```

`corctf{LKAPFECMDINHGBJO}`