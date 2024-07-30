---
title: lucky roll gaming
date: 2024-03-05
tags: 
- crypto
- LLL
- author-tomato
categories: osu!gamingCTF 2024
---

> my friend gamillie keeps losing their rolls!! help them predict when to roll so they can secure first pick and win their match!!

We are given `script.py`:

{% ccb 
caption:script.py
lang:python
gutter1:1-32
%}

from Crypto.Util.number import getPrime # https://pypi.org/project/pycryptodome/
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from random import randrange
from math import floor

def lcg(s, a, b, p):
    return (a * s + b) % p

p = getPrime(floor(72.7))
a = randrange(0, p)
b = randrange(0, p)
seed = randrange(0, p)
print(f"{p = }")
print(f"{a = }")
print(f"{b = }")

def get_roll():
    global seed
    seed = lcg(seed, a, b, p)
    return seed % 100

out = []
for _ in range(floor(72.7)):
    out.append(get_roll())
print(f"{out = }")

flag = open("flag.txt", "rb").read()
key = bytes([get_roll() for _ in range(16)])
iv = bytes([get_roll() for _ in range(16)])
cipher = AES.new(key, AES.MODE_CBC, iv)
print(cipher.encrypt(pad(flag, 16)).hex())

{% endccb %}

and its output in `out.txt`.

So, its a PRNG cracking challenge. Their PRNG is an LCG of the form {%katex%}X_{n+1}=(a*X_n+b) \pmod{p}{%endkatex%} where {%katex%}a,b,p{%endkatex%} are given. Except, we only get the outputs {%katex%}\pmod{100}{%endkatex%}. So, we have to try to find a seed that will give us the exact 72 outputs they say, {%katex%}\pmod{100}{%endkatex%}.


## LLL

I see LCG, I think LLL.

