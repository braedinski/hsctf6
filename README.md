# HSCTF 6

A bunch of write-ups for HSCTF 6 which I participated in this year. The write-ups are mostly for binary exploitation and reverse engineering. The first few web challenges were pretty easy so I didn't bother doing write-ups.

## Challenges

|Challenge|Type|
|---------|-----|
|[English Sucks](#english-sucks)|misc|

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
