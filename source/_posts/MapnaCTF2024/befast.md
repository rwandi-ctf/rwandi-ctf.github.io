---
title: Be fast
date: 2024-01-23
tags: crypto
categories: MapnaCTF 2024
---

solved by {% person tomato %}

> Rapid mastery of breaking symmetric encryption, deciphering codes with precision, and navigating complexities with unprecedented speed and efficiency are requirements for every professional cryptographer. So, be fast.

{% ccb caption:be_fast.py
lang:py
scrollable:true
gutter1:1-87%}

#!/usr/bin/env python3

from random import *
from binascii import *
from Crypto.Cipher import DES
from signal import *
import sys, os
from flag import flag

def die(*args):
	pr(*args)
	quit()

def pr(*args):
	s = " ".join(map(str, args))
	sys.stdout.write(s + "\n")
	sys.stdout.flush()

def sc():
	return sys.stdin.buffer.readline()

def shift(msg, l):
	assert l < len(msg)
	return msg[l:] + msg[:l]

def pad(text):
	if len(text) % 8 != 0:
		text += (b'\xff' * (8 - len(text) % 8))
	return text

def encrypt(msg, key):
	msg = pad(msg)
	assert len(msg) % 8 == 0
	assert len(key) == 8
	des = DES.new(key, DES.MODE_ECB)
	enc = des.encrypt(msg)
	return enc

def main():
	border = "+"
	pr(border*72)
	pr(border, ".::        Hi all, you should be fast, I mean super fact!!       ::.", border)
	pr(border, "You should send twenty 8-byte keys to encrypt the secret message and", border)
	pr(border, "just decrypt the ciphertext to get the flag, Are you ready to start?", border)
	pr(border*72)

	secret_msg = b'TOP_SECRET:' + os.urandom(40)
	
	cnt, STEP, KEYS = 0, 14, []
	md = 1

	while True:
		pr(border, "please send your key as hex: ")
		alarm(md + 1)
		ans = sc().decode().strip()
		alarm(0)
		try:
			key = unhexlify(ans)
			if len(key) == 8 and key not in KEYS:
				KEYS += [key]
				cnt += 1
			else:
				die(border, 'Kidding me!? Bye!!')
		except:
			die(border, 'Your key is not valid! Bye!!')
		if len(KEYS) == STEP:
			print(KEYS)
			HKEY = KEYS[:7]
			shuffle(HKEY)
			NKEY = KEYS[-7:]
			shuffle(NKEY)
			for h in HKEY: NKEY = [key, shift(key, 1)] + NKEY
			enc = encrypt(secret_msg, NKEY[0])
			for key in NKEY[1:]:
				enc = encrypt(enc, key)
			pr(border, f'enc = {hexlify(enc)}')
			pr(border, f'Can you guess the secret message? ')
			alarm(md + 1)
			msg = sc().strip()
			alarm(0)
			if msg == hexlify(secret_msg):
				die(border, f'Congrats, you deserve the flag: {flag}')
			else:
				die(border, f'Sorry, your input is incorrect! Bye!!')

if __name__ == '__main__':
	main()

{% endccb %}

The server lets us submit fourteen 8-byte keys, and then uses the keys to encrypt the plaintext somehow, and we need to quickly decrypt the ciphertext given.

## The encryption

{% ccb 
lang:py
gutter1:57-65
%}

		try:
			key = unhexlify(ans)
			if len(key) == 8 and key not in KEYS:
				KEYS += [key]
				cnt += 1
			else:
				die(border, 'Kidding me!? Bye!!')
		except:
			die(border, 'Your key is not valid! Bye!!')

{% endccb %}

Our fourteen keys must be different, and are stored in variable `KEYS`. Also, note that the `key` variable stores the last key we submitted.

{% ccb
lang:py
gutter1:68-71
%}

			HKEY = KEYS[:7]
			shuffle(HKEY)
			NKEY = KEYS[-7:]
			shuffle(NKEY)

{%endccb%}

First 7 keys go to `HKEY`, last 7 go to `NKEY`. Both are shuffled now.

{% ccb 
lang:py
gutter1:22-24,S,72
%}

def shift(msg, l):
	assert l < len(msg)
	return msg[l:] + msg[:l]
//SKIP_LINE:(25-71)
for h in HKEY: NKEY = [key, shift(key, 1)] + NKEY

{% endccb %}

Recall that the `key` variable stores the last key we submitted. We add `[key, key[1:]+key[:1]]` to the front of `NKEY` 7 times.

{% ccb
lang:py
gutter1:31-37,S,73-75
%}

def encrypt(msg, key):
	msg = pad(msg)
	assert len(msg) % 8 == 0
	assert len(key) == 8
	des = DES.new(key, DES.MODE_ECB)
	enc = des.encrypt(msg)
	return enc
//SKIP_LINE:(38-72)
enc = encrypt(secret_msg, NKEY[0])
for key in NKEY[1:]:
    enc = encrypt(enc, key)

{%endccb%}

`encrypt` function pads the message, then uses [DES](https://en.wikipedia.org/wiki/Data_Encryption_Standard) in ECB mode to encrypt it. Using the keys from the `NKEY` variable, we encrypt the message with the first key, then encrypt the obtained ciphertext with the second key, etc. Basically, use every key from `NKEY` from left to right to repeatedly encrypt the message. (note `HKEY` is just not used)

## The decryption

So, we need to reverse the DES encryptions to somehow obtain the original plaintext. If we call our last submitted key `k`, the plaintext undergoes encryptions by `k, shift(k)` 7 times in a row, and then our last 7 submitted keys in a shuffled order.

Since we know which key is used in the first 14 encryptions, we can shift it ourselves and just straight up do the decryption from there, provided that we are able to decrypt the last 7 encryption with shuffled keys. So, that is not a problem and now we just need to crack the encryption by 7 keys in a random order.

Since it is only 7 keys, we might consider just brute forcing all 7!=5040 orders of keys to see which one is correct. I didn't verify whether this can be done fast enough, but it seems like the author wanted to prevent this due to the many `alarm`s.

### [DES](https://en.wikipedia.org/wiki/Data_Encryption_Standard)

DES is just an older version of AES (that is now known to be insecure). My first thought is having the encryptions in the shuffled 7 keys cancel out somehow. But, unlike AES, encrypting and re-encrypting a plaintext with the same key in DES does not result in the original plaintext. Encryption and decryption algorithms for DES have slight differences, so even if we submitted the same key twice somehow, it would just encrypt the plaintext twice.

But, reading through the wikipedia page for DES, we find that there seems to be a class of [weak keys](https://en.wikipedia.org/wiki/Weak_key#Weak_keys_in_DES) for DES. The weak keys (call them {%katex%}k{%endkatex%}) have the property that 

{% katex '{ "displayMode": true }' %}
E_k(E_k(m))=m
{% endkatex %}

which is similar to AES. However, this is [not helpful](#note) as we cannot submit the same key {%katex%}k{%endkatex%} twice. There are however, semi-weak keys which come in pairs {%katex%}k_1, k_2{%endkatex%} that have the property that

{% katex '{ "displayMode": true }' %}
E_{k_1}(E_{k_2}(m))=m
{% endkatex %}

which is certainly helpful. If we submit three pairs of weak keys, we can pray that they align properly and cancel out, leaving us with only the final key to decrypt with. After testing, I discovered that this is satisfied roughly 1 in 10 times by chance. 

## Python implementation

```py
from Crypto.Util.number import long_to_bytes as ltb, bytes_to_long as btl
from pwn import *
import os
from Crypto.Cipher import DES

def shift(msg, l):
    assert l < len(msg)
    return msg[l:] + msg[:l]

def pad(text):
    if len(text) % 8 != 0:
        text += (b'\xff' * (8 - len(text) % 8))
    return text

def encrypt(msg, key):
    msg = pad(msg)
    assert len(msg) % 8 == 0
    assert len(key) == 8
    des = DES.new(key, DES.MODE_ECB)
    enc = des.encrypt(msg)
    return enc

def decrypt(msg, key):
    msg = pad(msg)
    assert len(msg) % 8 == 0
    assert len(key) == 8
    des = DES.new(key, DES.MODE_ECB)
    enc = des.decrypt(msg)
    return enc

HKEY = [os.urandom(8) for _ in range(7)]
weak = [0x011F011F010E010E, 0x1F011F010E010E01, 0x01E001E001F101F1, 0xE001E001F101F101, 0x01FE01FE01FE01FE, 0xFE01FE01FE01FE01]
NKEY = [8*b"\x00"] + [ltb(i) for i in weak]

conn = remote("3.75.180.117", 37773)
conn.recvuntil(b"start? +\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")

for k in HKEY+NKEY:
    conn.sendline(k.hex().encode())
for k in HKEY+NKEY:
    conn.recvline()

conn.recvline()
line = conn.recvline()
conn.recvline()

enc = eval(line.decode().split(" ")[-1])
enc = bytes.fromhex(enc.decode())
enc = encrypt(enc, 8*b"\x00")
k = ltb(weak[-1])
for key in (7*[k, shift(k, 1)])[::-1]:
    enc = decrypt(enc, key)
conn.sendline(enc[:-5].hex().encode()) # Remember to unpad the plaintext!!!
result = conn.recvline()

print(f"result: {result}")
```

giving the flag `MAPNA{DES_h4s_A_f3W_5pec1f!c_kEys_7eRm3d_we4K_k3Ys_And_Sem1-wE4k_KeY5!}`

### note
I later realized that since the least significant bit of DES keys does not matter (they are used as parity bits apparently), these weak keys can still be used by just flipping their lsb.