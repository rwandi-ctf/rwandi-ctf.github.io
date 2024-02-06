---
title: rps-casino
date: 2024-02-06
tags: 
- crypto
- author-tomato
categories: DiceCTF 2024
---

solved by {% person tomato %}

> We're opening a new casino! The only game is rock-paper-scissors though...

We are given

{% ccb caption:mac.py 
lang:py
url_text:source  
scrollable:true
gutter1:1-47 %}

#!/usr/local/bin/python

import os
from Crypto.Util.number import bytes_to_long

def LFSR():
	state = bytes_to_long(os.urandom(8))
	while 1:
		yield state & 0xf
		for i in range(4):
			bit = (state ^ (state >> 1) ^ (state >> 3) ^ (state >> 4)) & 1
			state = (state >> 1) | (bit << 63)

rng = LFSR()

n = 56

print(f"Let's play rock-paper-scissors! We'll give you {n} free games, but after that you'll have to beat me 50 times in a row to win. Good luck!")
rps = ["rock", "paper", "scissors", "rock"]

nums = []
for i in range(n):
	choice = next(rng) % 3
	inp = input("Choose rock, paper, or scissors: ")
	if inp not in rps:
		print("Invalid choice")
		exit(0)
	if inp == rps[choice]:
		print("Tie!")
	elif rps.index(inp, 1) - 1 == choice:
		print("You win!")
	else:
		print("You lose!")

for i in range(50):
	choice = next(rng) % 3
	inp = input("Choose rock, paper, or scissors: ")
	if inp not in rps:
		print("Invalid choice")
		break
	if rps.index(inp, 1) - 1 != choice:
		print("Better luck next time!")
		break
	else:
		print("You win!")
else:
	print(open("flag.txt").read())

{% endccb %}

We get to play RPS `n=56` times before having to win 50 times in a row. The computer's choice is based on an LFSR. Hehehe z3.

```py
from pwn import *
from z3 import *

n = 56
mapa = {b"Tie!": 0, b"You win!": 2, b"You lose!": 1}
rps = ["rock", "paper", "scissors", "rock"]

conn = remote("mc.ax", 31234)
conn.recvuntil(": ")

for _ in range(n): conn.sendline("rock")
results = [conn.recvuntil(": ") for _ in range(n)]
results = [mapa[l.split(b"\n")[0]] for l in results]

state = BitVec("state", 64)
stateref = state
solver = Solver()
for j in range(n):
    solver.add((state & 0xf)%3 == results[j])
    for i in range(4):
        bit = (state ^ LShR(state, 1) ^ LShR(state, 3) ^ LShR(state, 4)) & 1 # [-1]^[-2]^[-4]^[-5]
        state = LShR(state, 1) | (bit << 63) # append to front and lose last

solver.check()
state = solver.model()[stateref].as_long()
lfsr = LFSR(state)
[next(lfsr) for _ in range(n)]

for _ in range(50):
    conn.sendline(rps[(next(lfsr)+1)%3])

for _ in range(49):
    conn.recvuntil(": ")

print(conn.recv())
```

giving the flag `dice{wow_u_must_be_extremely_lucky_91ff5a34}`.