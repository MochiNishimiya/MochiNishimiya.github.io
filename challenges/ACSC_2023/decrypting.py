# --------------------------------
# ========== DECRYPTION ==========
# --------------------------------

li = [246, 3, 240, 42, 116, 9, 9, 200, 15, 102, 163, 229, 239, 55, 44, 206, 68, 223, 244, 107, 222, 181, 73, 79, 56, 79, 213, 16, 113, 204, 231, 106, 168, 116, 83, 216, 59, 75, 5, 67, 93, 180, 204, 239, 215, 136, 160, 114, 240, 201, 130, 221, 189, 39, 247, 153, 22, 198, 97, 141, 187, 21, 178, 157]

inp = []
inp.append((-0x73) & 0xff)
inp.append(109)
inp.append((-82) & 0xff)
inp.append(0x53)
inp.append(0xb5)
inp.append(39)
inp.append(0xf)
inp.append(0x31)
inp.append(0xe2)
inp.append(0x6e)
inp.append(18)
inp.append((-12 + 1) & 0xff)
inp.append(75)
inp.append((-127 + 1) & 0xff)
inp.append(20)
inp.append(67 + 1)

inp.append((-24) & 0xff)
inp.append(0xc7)
inp.append(32)
inp.append(0xef)
inp.append(32 + 1)
inp.append(11 + 1)
inp.append(0x3d)
inp.append(0x1b)
inp.append(21 + 1)
inp.append((-125 + 1) & 0xff)
inp.append(0x91)
inp.append((-12 + 1) & 0xff)
inp.append(0x89)
inp.append(0xd1)
inp.append(26 + 1)
inp.append((-122) & 0xff)

inp.append(0x8a)
inp.append(0xef)
inp.append(0xad)
inp.append((-15 + 1) & 0xff)
inp.append(0xda)
inp.append((-53) & 0xff)
inp.append((87 + 1) & 0xff)
inp.append((-46) & 0xff)
inp.append(0xb0)
inp.append(81)
inp.append(0x2a)
inp.append(0x63)
inp.append(0x93)
inp.append((-59 + 1) & 0xff)
inp.append(0xe7)
inp.append(0xb0)

inp.append(0x11)
inp.append((-103) & 0xff)
inp.append((-107) & 0xff)
inp.append((-14 + 1) & 0xff)
inp.append(53)
inp.append(0xe)
inp.append(0xd1)
inp.append(0x58)
inp.append(0x84)
inp.append(0x7c)
inp.append(0x55)
inp.append(80 + 1)
inp.append((-73) & 0xff)
inp.append(0xcf)
inp.append((-89) & 0xff)
inp.append(0x57)

ans = []
for i in range(len(inp)):
    stat = 0
    for c in range(256):
        if (5889 * (((c ^ li[i]) & 0xff) + 2 * ((li[i] & c) & 0xff)) + 3584) & 0xff == inp[i]:
            ans.append(c)
            stat = 1
            break
    # break
    if stat == 0:
        print('something is wrong')
        exit(0)
print()

for indexing in range(255, -1, -1):
    v34 = 0
    ans[second_index[indexing]] ^= v27_arr[indexing]
    if ((indexing ^ v27_arr[indexing]) & 0xff > 3):
        ans[first_index[indexing]] = ans[first_index[indexing]] ^ ans[second_index[indexing]] ^ indexing
    else:
        ans[first_index[indexing]] = ans[first_index[indexing]] ^ indexing

num = 0
for i in ans:
    num += 1
    print(chr(i & 0xff), end = '')
print()