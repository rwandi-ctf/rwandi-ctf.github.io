---
title: hOlyT
date: 2024-02-19
tags: 
- crypto
- author-tomato
categories: LACTF 2024
---

solved by {% person tomato %}

> God is trying to talk to you through a noisy wire
> 
> Use nc chall.lac.tf 31171 to talk to him.

{% ccb caption:server.py 
lang:py
scrollable:true
gutter1:1-73 %}

from Crypto.Util.number import getPrime, bytes_to_long
import random
def legendre(a, p):
    return pow(a, (p - 1) // 2, p)

def tonelli(n, p):
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    if s == 1:
        return pow(n, (p + 1) // 4, p)
    for z in range(2, p):
        if p - 1 == legendre(z, p):
            break
    c = pow(z, q, p)
    r = pow(n, (q + 1) // 2, p)
    t = pow(n, q, p)
    m = s
    t2 = 0
    while (t - 1) % p != 0:
        t2 = (t * t) % p
        for i in range(1, m):
            if (t2 - 1) % p == 0:
                break
            t2 = (t2 * t2) % p
        b = pow(c, 1 << (m - i - 1), p)
        r = (r * b) % p
        c = (b * b) % p
        t = (t * c) % p
        m = i
    return r
def xgcd(a, b): 
    if a == 0 : 
        return 0,1
             
    x1,y1 = xgcd(b%a, a) 
    x = y1 - (b//a) * x1 
    y = x1 
     
    return x,y 
def crt(a, b, m, n):
    m1, n1 = xgcd(m, n)
    return ((b *m * m1 + a *n*n1) % (m * n))

def advice(x, p, q):
    if legendre(x, p) != 1:
        exit()
    if legendre(x, q) != 1:
        exit()
    x1 = tonelli(x, p) * random.choice([1, -1])
    x2 = tonelli(x, q) * random.choice([1, -1])
    y = crt(x1, x2, p, q)
    return y
    
def main():
    p = getPrime(1024)
    q = getPrime(1024)
    N = p * q
    e = 65537
    m = bytes_to_long(b"lactf{redacted?}")
    ct = pow(m, e, N)
    print(f"ct = {ct}")
    print(f"N = {N}")
    print(f"e = {e}")
    while 1:
        x = int(input("What do you want to ask? > "))
        ad = advice(x, p, q)
        print(ad)

if __name__ == "__main__":
    main()

{% endccb %}

We are given an oracle that allows us to "ask for advice". It encrypts the flag using RSA with 1024-bit primes, giving us the ciphertext and modulus, and we are allowed to get information about the primes `p` and `q`.

To be more specific, we are allowed to submit an integer `x`, then it runs the `advice` function.

Lets look at `advice`:

{% ccb 
lang:py
gutter1:47-55
%}

def advice(x, p, q):
    if legendre(x, p) != 1:
        exit()
    if legendre(x, q) != 1:
        exit()
    x1 = tonelli(x, p) * random.choice([1, -1])
    x2 = tonelli(x, q) * random.choice([1, -1])
    y = crt(x1, x2, p, q)
    return y

{% endccb %}

It first ensures the [legendre symbol](https://en.wikipedia.org/wiki/Legendre_symbol) of `x` mod `p` and `x` mod `q` are 1, aka `x` is a quadratic residue both mod `p` and mod `q`, aka there exists integers `m` and `n` such that

{% katex '{ "displayMode": true }' %}
x \equiv m^2 \pmod{p}\\
x \equiv n^2 \pmod{q}
{% endkatex %}

This is so that you can actually take the square root of `x` mod `p` and `q`, which is what [tonelli](https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm) does in the next step. After taking the square root, it randomly multiplies by 1 or -1, then it does [CRT](https://en.wikipedia.org/wiki/Chinese_remainder_theorem) on the following congruence relation:

{% katex '{ "displayMode": true }' %}
y \equiv \pm \sqrt{x} \pmod{p}\\
y \equiv \pm \sqrt{x} \pmod{q}
{% endkatex %}

So, with any such suspicious oracle, we just try submitting corner cases. Submitting 0 just gives {% katex %}y = 0{% endkatex %}, so not helpful. But if we submit 1, we know {% katex %}\sqrt{1} = 1 \pmod{p \text{ or } q}{% endkatex %}. 

If both are positive, then we just get {% katex %}y = 1{% endkatex %}, not helpful.
If both are negative, then we just get {% katex %}y = pq - 1 = n-1{% endkatex %}, not helpful.
But, if one is positive and the other is negative, for example, we get

{% katex '{ "displayMode": true }' %}
y \equiv -1 \pmod{p}\\
y \equiv 1 \pmod{q}
{% endkatex %}

This means that we have {% katex %}p \vert y+1{% endkatex %} and {% katex %}q \vert y-1{% endkatex %}. So, using the very powerful `gcd`, we can just do (most likely) {% katex %}p = \gcd{(y+1, n)}{% endkatex %} and {% katex %}q = \gcd{(y-1, n)}{% endkatex %}, so we win.

The solve is so simple that I don't have a solve script (bc I just copied from terminal and pasted into a random notebook), and I also forgot the flag oops but pretty simple concept.