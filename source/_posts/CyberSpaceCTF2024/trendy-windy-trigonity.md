---
title: trendy windy trigonity
date: 2024-09-17
tags:
- author-tomato
- LLL
categories: CyberSpaceCTF 2024
---

solved by {% person tomato %}

> have you seen Tan challenge before? see maple version pi documentation!

This is just a code dump or so, youtube video writeup is [here](https://youtu.be/vREqxm0j784).

{% ccb caption:chall.py
lang:py
url_text:source  
scrollable:true
gutter1:1-21 %}
from pwn import xor
from random import randint
from hashlib import sha256
from FLAG import flag

cc = [randint(-2**67, 2**67) for _ in range(9)]
key = sha256("".join(str(i) for i in cc).encode()).digest()
enc = xor(key, flag)

def superfnv():
    x = 2093485720398457109348571098457098347250982735
    k = 1023847102938470123847102938470198347092184702
    for c in cc:
        x = k * (x + c)
    return x % 2**600

print(f"{enc.hex() = }")
print(f"{superfnv() = }")

# enc.hex() = '4ba8d3d47b0d72c05004ffd937e85408149e13d13629cd00d5bf6f4cb62cf4ca399ea9e20e4227935c08f3d567bc00091f9b15d53e7bca549a'
# superfnv() = 2957389613700331996448340985096297715468636843830320883588385773066604991028024933733915453111620652760300119808279193798449958850518105887385562556980710950886428083819728334367280
{% endccb %}

Solve using LLL:
```py
# sage
from Crypto.Util.number import bytes_to_long as btl, long_to_bytes as ltb
R = RealField(1000)
x = R(0.75872961153339387563860550178464795474547887323678173252494265684893323654606628651427151866818730100357590296863274236719073684620030717141521941211167282170567424114270941542016135979438271439047194028943997508126389603529160316379547558098144713802870753946485296790294770557302303874143106908193100)
res = 2.78332652222000091147933689155414792020338527644698903976732528036823470890155538913578083110732846416012108159157421703264608723649277363079905992717518852564589901390988865009495918051490722972227485851595410047572144567706501150041757189923387228097603575500648300998275877439215112961273516978501e45

c = round(cos(x) * 10^300)
s = round(sin(x) * 10^300)
r = round(res * 10^300)
L = Matrix([
    [c, 1, 0, 0],
    [s, 0, 1, 0],
    [-r, 0, 0, 1]
])
W = diagonal_matrix(
    [1, 1, 1, 1]
)
reduced = (L*W).LLL()/W
assert reduced[0][-1]==1
a,b = reduced[0][1:3]
ltb(int(a)) + ltb(int(b))
```

giving the flag `CSCTF{Trigo_453_Tr3ndy_FuN_Th35e_D4Y5}`