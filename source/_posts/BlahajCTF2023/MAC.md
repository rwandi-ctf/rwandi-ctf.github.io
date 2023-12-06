---
title: MAC
date: 2023-12-05
tags: crypto
categories: BlahajCTF 2023
---

solved by {% person tomato %}

> mom can we have MAC? no there is MAC at blahajctf MAC at blahajctf:

{% ccb caption:mac.py 
lang:py
url:gist.github.com/azazazo/96f83ffa7ed59850da4e52eeec5fa08b
url_text:source  
scrollable:true
gutter1:1-41 %}

import random
from Crypto.Util.number import bytes_to_long as b2l

FLAG = "blahaj{???}"

def MAC(message, key):
    key += 1<<32
    assert key.bit_length() == 33, key

    m = b2l(message.encode())
    l = m.bit_length()
    m <<= 32

    for i in range(l-1, -1, -1):
        if (m >> (i+32)) & 1:
            m ^= key << i
    
    return hex(m)[2:]

while True:
    print("Options:")
    print("[1] Test MAC")
    print("[2] Verify MAC")
    print("[3] Get flag")
    i = int(input(">> "))
    if i == 1:
        message = input("Message: ")
        key = random.getrandbits(32)
        print(f"Your MAC is {MAC(message, key)} with key {hex(key)[2:]}")
    elif i == 2:
        message = input("Message: ")
        key = int(input("Key: "), 16)
        mac = input("MAC: ")
        print(MAC(message, key))
        if MAC(message, key) == mac:
            print("Verified!")
        else:
            print("Not verified!")
    elif i == 3:
        key = random.getrandbits(32)
        print(f"MAC of flag is {MAC(FLAG, key)}")

{% endccb %}

We are given an oracle containing a MAC algorithm, from which we can either test creating MACs, verify a MAC, or get the MAC of the flag.

First, we determine what the MAC algorithm does (this aint a normal MAC)

## The algorithm

{% ccb 
lang:py
gutter1:6-18
%}

def MAC(message, key):
    key += 1<<32
    assert key.bit_length() == 33, key

    m = b2l(message.encode())
    l = m.bit_length()
    m <<= 32

    for i in range(l-1, -1, -1):
        if (m >> (i+32)) & 1:
            m ^= key << i
    
    return hex(m)[2:]

{% endccb %}

First, we add `1<<32` (1 followed by 32 0s in binary) to key, and assert that it is 33 bits. Then, we bit-shift m to the left by `32`, essentially appending 32 0s to the end of m in binary.

Finally, in the actual algorithm, we loop `i` from `m.bit_length()-1` to `0`, in each iteration first check if `(m >> (i+32)) & 1`

What this does is first truncate `i+32` bits off the right of `m` by bit-shifting it to the right, and then check if the least significant (last) bit remaining is a 1. Essentially, checking if the `i+33`rd last bit is 1.

If so, then we do `m ^= key << i`. This shifts the key to the left by `i` bits, then xors it with the key at that location. Since the key is 33 bits, the start of the key would then be at the `i+33`rd last bit as well.

So, essentially the algorithm goes from left to right on the message, and whenever it sees a `1` bit, it places the key starting there (which is guaranteed to start with the bit `1` since we added `1>>32` to it), and then xors it there. This continues until checking the 33rd last bit, essentially ensuring that the entire ciphertext is pushed to the last 32 bits.

To visualize this better, I added these print statements to the algorithm:


{% ccb 
lang:py
gutter1:6,S,14-22
diff_add:5,6,9,10
%}

def MAC(message, key):
//SKIP_LINE:(7-13)
    for i in range(l-1, -1, -1):
        print(bin(m)[2:].zfill(64))
        print(bin(key<<i)[2:].zfill(64))
        if (m >> (i+32)) & 1:
            m ^= key << i
            print("xored")
        else: print("not xored")
    
    return hex(m)[2:]

{% endccb %}

Running `MAC("Z", random.getrandbits(32))` now gives: (key is underlined)

{% ccb
html:true %}
0000000000000000000000000<span style="color:#F99157">1</span>01101000000000000000000000000000000000
0000000000000000000000000<u><span style="color:#F99157">1</span>10100001110010101101110011110100</u>000000
xored
00000000000000000000000000<span style="color:#F99157">1</span>1001001110010101101110011110100000000
00000000000000000000000000<u><span style="color:#F99157">1</span>10100001110010101101110011110100</u>00000
xored
000000000000000000000000000<span style="color:#F99157">0</span>011001001011111011001010001110000000
000000000000000000000000000<u><span style="color:#F99157">1</span>10100001110010101101110011110100</u>0000
not xored
0000000000000000000000000000<span style="color:#F99157">0</span>11001001011111011001010001110000000
0000000000000000000000000000<u><span style="color:#F99157">1</span>10100001110010101101110011110100</u>000
not xored
00000000000000000000000000000<span style="color:#F99157">1</span>1001001011111011001010001110000000
00000000000000000000000000000<u><span style="color:#F99157">1</span>10100001110010101101110011110100</u>00
xored
000000000000000000000000000000<span style="color:#F99157">0</span>011001100110001111101000001010000
000000000000000000000000000000<u><span style="color:#F99157">1</span>10100001110010101101110011110100</u>0
not xored
0000000000000000000000000000000<span style="color:#F99157">0</span>11001100110001111101000001010000
0000000000000000000000000000000<u><span style="color:#F99157">1</span>10100001110010101101110011110100</u>
not xored
{% endccb %}

Ok, but what can we do with this algorithm? The oracle allows us to test the MAC by:
1. Submitting a message
2. Receiving the MAC as well as the random key used (generated with `random.getrandbits(32)`). 

For the flag part, we can receive the MAC of the flag, but not the random key used for it. 

Obviously reversing the MAC algorithm would be impossible without the key, so we have to get the key somehow. Fortunately, since it is an oracle, we can simply query the test MAC 624 times to receive 624 successive outputs of `random.getrandbits(32)`, just enough to predict every future output of the function ([randcrack](https://github.com/tna0y/Python-random-module-cracker)).

Now, given as many pairs of key and flag MAC as we want, how can we recover the flag?

## Solution

The key idea is to notice that this algorithm is kinda similar to long division. In long division, you also go from left to right looking for a place where you can put the divisor, then subtract it and move on. But how can we treat these xors as division?

### GF(2^n)

We need to somehow turn the xor operation into subtraction. To do this, we should take a closer look at how the xor operation works. It has these 4 cases:

{% katex '{ "displayMode": true }' %}
0 \oplus 0 = 0\\
0 \oplus 1 = 1\\
1 \oplus 0 = 1\\
1 \oplus 1 = 0
{% endkatex %}

And if you want to force this into a subtraction, when you squint really hard you can see that this is the same as subtraction under modulo 2. Hence, to emulate a xor, we can just do operations under a Galois field (aka finite field) with 2 elements, aka GF(2). 

This just means we do operations within the set of integers modulo 2 (in this case just 0 and 1), and define all arithmetic operations also under the modulo.

But obviously, we aren't dealing with single bits here, but numbers with multiple bits, so instead of GF(2) here, we can use GF(2)^n=GF(2^n), which is comprised of bit vectors of length n, for example in GF(2^3):

{% katex '{ "displayMode": true }' %}
6 = \begin{pmatrix}
1\\1\\0
\end{pmatrix}
{% endkatex %}

These are commonly equivalently represented as polynomials of degree n-1 or less, so in this case:

{% katex '{ "displayMode": true }' %}
1 \cdot x^2 + 1 \cdot x + 0
{% endkatex %}

Now, we can do xors on numbers by instead subtracting (or adding) their polynomial representations under GF(2^n). For example, we can do {%katex%}6 \oplus 3{%endkatex%} instead like:

{% katex '{ "displayMode": true }' %}
(x^2 + x) + (x + 1) = (x^2 + 1)
{% endkatex %}

under GF(2^3). {%katex%}x^2+1{%endkatex%} has coefficients 1, 0, 1 which would be binary of 5, so {%katex%}6 \oplus 3=5{%endkatex%}.

With this, we can now actually do long division.

Going back to the MAC algorithm, at the stage where we start doing the division, the dividend is `m<<32`, and the divisor is `key+(1<<32)`. After doing all the dividing, the number left is the MAC, which would hence be the remainder. Now, we can go to sage to construct these GF(2^n) polynomials and see if the remainder matches.

Running the following in py:

```py
int(MAC("test",1209359071),16)
```

gives `2379082471`, and now implementing the polynomial version in sage:

```py
R.<x> = PolynomialRing(GF(2),'x')
def num2poly(num):
    return sum(int(j)*x^i for i,j in enumerate(bin(num)[2:][::-1]))
def poly2num(poly):
    return int("".join(map(str,poly.list()[::-1])),2)
a = num2poly(b2l(b"test")) * x^32
b = num2poly(1209359071) + x^32
poly2num(a.quo_rem(b)[1])
```

also gives `2379082471`. GG!

### crt

Now, how to use this to get the flag? What this essentially means, is that if we call the flag polynomial {%katex%}f(x){%endkatex%}, we have a bunch of pairs of a polynomial {%katex%}a(x){%endkatex%} and the remainder leftover when dividing {%katex%}f(x){%endkatex%} by {%katex%}a(x){%endkatex%}. A bunch of divisors and their corresponding remainders, sound familiar? 

It's the Chinese remainder theorem. If you don't know CRT, it basically states that the system of congruences

{% katex '{ "displayMode": true }' %}
\begin{aligned}
x &\equiv a_1 \pmod{n_1}\\
& \vdots\\
x &\equiv a_k \pmod{n_k}
\end{aligned}
{% endkatex %}

is solveable for {%katex%}x{%endkatex%} given that {%katex%}n_i{%endkatex%} are all coprime, where all solutions will be equivalent modulo {%katex%}\prod n_i{%endkatex%}.

But, can CRT be applied to polynomials? Searching it up, the Extended Euclidean algorithm that can be used to construct solutions for the traditional CRT on integers, also works for polynomials. So, it should work, and sage's inbuilt `CRT` function conveniently works for polynomials. With CRT, we can now recover the flag polynomial given that we have enough divisor polynomials such that they multiply together to be greater than the flag polynomial.

So, now we just implement everything together by:

1. Query "Test MAC" 624 times (at least) to receive enough keys to predict all future keys
2. Query "Get flag" 100 times to receive enough flag MACs in order to recover the flag with CRT
3. Predict the keys used in making the flag MACs using [randcrack](https://github.com/tna0y/Python-random-module-cracker)
4. Apply polynomial CRT to recover the flag

## Full sage implementation

```py
from Crypto.Util.number import long_to_bytes as l2b, bytes_to_long as b2l
from pwn import *
from randcrack import RandCrack

conn = remote("146.190.6.88",30003r)
conn.recvuntil(">> ")
for _ in range(625):
    conn.sendline("1")
    conn.sendline("a")
rec=[]
for _ in range(625):
    rec.append(conn.recvuntil(">> "))
for _ in range(100):
    conn.sendline("3")
rec3=[]
for _ in range(100):
    rec3.append(conn.recvuntil(">> "))
    
rec2 = [int(i.decode().split("\n")[0].split()[-1],16) for i in rec] # 625 successive keys

# Recover next 100 keys:
rc = RandCrack()
for i in rec2[:624]:
    rc.submit(i)
rc.predict_getrandbits(32)
keys = [rc.predict_getrandbits(32) for _ in range(100)]

rec4 = [int(i.decode().split("\n")[0].split()[-1],16) for i in rec3] # 100 flag MACs

# CRT:
R.<x> = PolynomialRing(GF(2),'x')

def num2poly(num):
    return sum(int(j)*x^i for i,j in enumerate(bin(num)[2:][::-1]))
def poly2num(poly):
    return int("".join(map(str,poly.list()[::-1])),2)
num2poly(b2l(b"test"))

flagpoly = crt([num2poly(i) for i in rec4], [num2poly(i)+x^32 for i in keys])>>32
l2b(poly2num(flagpoly))
```

giving the flag `blahaj{cRc_m0RE_l1ke_Cr7}`

