---
title: RC4 Signing Scheme
date: 2024-07-31
tags: 
- crypto
- author-tomato
categories: greyCTF finals 2024
---

> 1024-bit (secure!) signing algorithm with RC4 (fast!)
> author: hadnot
> 3 solves

{% ccb 
caption:rc4-signing-scheme.py
scrollable:true
lang:py
gutter1:1-90
%}
import os

with open("flag.txt", "r") as f:
    flag = f.read().encode()

def keyschedule(key):
    S = list(range(256))
    j = 0
    for i in range(256):
         j = (j + S[i] + key[i%len(key)])%256
         t = S[i]
         S[i] = S[j]
         S[j] = t
    return S

def encrypt(S, pt):
    ct = bytes([])
    i = 0
    j = 0
    for x in pt:
        i = (i+1)%256
        j = (j+S[i])%256
        t = S[i]
        S[i] = S[j]
        S[j] = t
        t = (S[i] + S[j])%256
        ct += bytes([S[t] ^ x])
    return ct

def sign(msg):

    global num_encryptions
    num_encryptions += 1
    if (num_encryptions > 20):
        # no more for you...
        return b""
    
    iv = os.urandom(128)
    USED_IVS.append(iv)
    key = iv + priv_key
    S = keyschedule(key)
    ct = encrypt(S, msg)
    return iv + ct

def verify(msg, sig):

    iv, ct = sig[:128], sig[128:]
    
    if iv in USED_IVS:
        # thats too easy...
        return False

    key = iv + priv_key
    S = keyschedule(key)
    pt = encrypt(S, ct)
    return msg == pt

menu = """
Enter an option:
[1] Sign secret
[2] Submit signature
[3] Exit
> """

num_encryptions = 0
USED_IVS = []
priv_key = os.urandom(128)
secret_msg = os.urandom(256)

while True:
    option = input(menu).strip()

    if option == "1":

        sig = sign(secret_msg)
        
        print(sig.hex())
                    
    elif option == "2":

        sig = bytes.fromhex(input("Signature (hex): "))
        
        if verify(secret_msg, sig):
            print(f"Wow! Here's the flag: {flag}")
            
        else:
            print("Wrong...")
            
    else:
        exit(0)
{% endccb %}

We are given an RC4 oracle where they can give us signatures of a secret message (with new random iv each time), and we have to forge a signature that doesn't reuse an already used iv. I don't want to read 90 lines of code. Luckily, RC4 is a [real](https://en.wikipedia.org/wiki/RC4) thing and they did implement it properly. RC4 is a stream cipher, meaning it produces a stream of numbers that are just xored with the plaintext. There are two steps:

### key scheduling

{% ccb 
lang:py
gutter1:6-14
%}
def keyschedule(key):
    S = list(range(256))
    j = 0
    for i in range(256):
         j = (j + S[i] + key[i%len(key)])%256
         t = S[i]
         S[i] = S[j]
         S[j] = t
    return S
{% endccb %}

This part is in order to create a permutation of `S`, an array of the numbers `0` to `255`, based on the 256-byte key. As you can see, it does this by storing an internal pointer `j` which jumps around. It iterates through `i` from `0` to `255`, at each iteration doing:

```py
j = (j + S[i] + key[i%len(key)])%256
swap S[i], S[j]
```

### prng + encrypt

{% ccb 
lang:py
gutter1:16-28
%}
def encrypt(S, pt):
    ct = bytes([])
    i = 0
    j = 0
    for x in pt:
        i = (i+1)%256
        j = (j+S[i])%256
        t = S[i]
        S[i] = S[j]
        S[j] = t
        t = (S[i] + S[j])%256
        ct += bytes([S[t] ^ x])
    return ct
{% endccb %}

Won't explain much here because its not actually relevant to this challenge, but basically does lookups and swaps based on the new permutation of S (continuing to permutate it) and spits out values (the stream) that can be xored with the plaintext to produce ciphertext

## signature?

RC4 is an encryption algorithm (and not even a secure one), so turning it into a signature scheme is bound to create issues. Here's how the challenge turned it into a signature:

{% ccb 
lang:py
gutter1:30-43
%}
def sign(msg):

    global num_encryptions
    num_encryptions += 1
    if (num_encryptions > 20):
        # no more for you...
        return b""
    
    iv = os.urandom(128)
    USED_IVS.append(iv)
    key = iv + priv_key
    S = keyschedule(key)
    ct = encrypt(S, msg)
    return iv + ct
{% endccb %}

The private key stored (which is reused) is only 128 bytes, so each time they want to sign, a new random 128-byte `iv` is created, and is appended to the front of the private key to form the key. Then, standard RC4 encryption is used to create the ciphertext `ct`, and the signature is then `iv + ct`. We can only receive 20 signatures of their secret message, afterwards we must forge a signature, aka a valid `iv + ct` combination.

The first strategy to try is to see if we can use an existing `ct`, but modify the `iv` to produce a secondary valid signature. After the key scheduling step, the only thing used going forward is the permutation of `S` generated, so if we can modify an `iv` to produce the same `S`, we win.

The way the key scheduling works, is `i` iterates from `0` to `255`, but `j` is incremented based on both the values of the key, and the values in the current `S`, then at each iteration it swaps the numbers at `S[i], S[j]`, doing a total of 256 swaps. Since I only have power over the first half of the key through `iv`, after the first 128 swaps I would need to leave the internal state (`S` and `j`) exactly the same for the rest of the signing to run the same way.

My first idea was to basically slightly modify successive swaps such that they produce the same outcome. For example, if the first two swaps are both self-swaps (meaning they don't change), then modifying those swaps to be swaps with one another would accomplish the same thing. (and vice versa) This would happen decently frequently, since every swap has a {%katex%}\frac{1}{256}{%endkatex%} chance to be a self-swap, and we just need two to happen in the first 128. Detecting self-swaps is also very easy, since the second half of the key doesn't matter until after the first 128 iterations, so we can just self-simulate the first half of key scheduling and track the value of `j` to detect self swaps.

Of course there are some details to iron out. Firstly, since the `S` array is being swapped around live, it can easily interfere with itself. If something interferes with the array between the first and second self-swap, we would have to be careful of the corrections we make. But, through trial and error, you can modify self-swaps to become two swaps that cancel out as follows:

If `iv[i]` and `iv[i+d]` are self-swaps, then modify:

1. `iv[i] <- iv[i] + d` (turn `i` self-swap into `i,i+d` swap)
2. `iv[i+1] <- iv[i+1] - d` (an extra `d` was added to `j` so we cancel that)
3. (since `S[i+d]` is now `S[i]` instead (which I assumed to be `i+d`, `i` respectively), its `d` lower, which allows an `i,i+d` swap instead of `i+d,i+d` swap without making any changes)
4. `iv[i+d+1] <- iv[i+d+1] + d` (from the last iteration, `j` is lower by `d` so we cancel that)

(all {%katex%}\pmod{256}{%endkatex%})

This works assuming no interference, but you can easily generalize this since the entire thing can be simulated, so you can just calculate the exact changes needed. But it worked in like 3 tries for me, here is the solve script:

```py
from pwn import *

win = []
def sussy(sig):
    iv = sig[:128]
    global win
    js = []
    S = list(range(256))
    j = 0
    for i in range(128):
        j = (j + S[i] + iv[i])%256
        t = S[i]
        S[i] = S[j]
        S[j] = t
        js.append(j)
    trus = [js[i] == i for i in range(128)]
    if trus.count(True)>=2:
        inds = [i for i, x in enumerate(trus) if x == True]
        i = inds[0]
        d = inds[1]-i
        print(i,i+d)
        iv = list(iv)
        iv[i] = (iv[i]+d)%256
        iv[i+1] = (iv[i+1]-d)%256
        iv[i+d+1] = (iv[i+d+1]+d)%256
        iv = bytes(iv)
        print("WIN")
        win.append(iv+sig[128:])

conn = remote("challs.nusgreyhats.org", 32001r)
sigs=[]
ivs=[]
win=[]
for _ in range(20):
    conn.recvuntil("> ")
    conn.sendline("1")
    sig = bytes.fromhex(conn.recvline().decode().strip())
    sigs.append(sig)
for i in range(20):
    if len(win)==0:
        sussy(sigs[i])
    else: break
if len(win)>0:
    conn.recvuntil("> ")
    conn.sendline("2")
    conn.recvuntil(": ")
    conn.sendline(win[0].hex())
    print(conn.recv())
```

giving the flag `grey{rc4_more_like_rcgone_amirite_q20v498n20}`.