---
title: beginner-lcg
date: 2024-11-29
tags: 
- crypto
- author-tomato
categories: BlahajCTF 2024
---

by {% person tomato %}

> I've started my own Local Consultative Group (LCG)! But only members get to know its secrets.

{% ccb caption:chal.py 
lang:py
url_text:source  
scrollable:true
gutter1:1-46 %}

from Crypto.Util.number import getPrime, bytes_to_long
from secrets import randbelow

FLAG = "blahaj{redacted}"
f = bytes_to_long(FLAG.encode())

def LCG(a, m, x, c):
    while True:
        x = (a * x + c) % m
        yield x

m = getPrime(128)
# you can have m
print(f"{m = }")
# but i'll derive all the other parameters from the secret flag!
a = f % m
x = (f >> 128) % m
c = (f >> 256) % m
rng = LCG(a, m, x, c)

outputs_left = 3

while True:
    option = input(f"""[1] See output ({str(outputs_left)} outputs left)
[2] Check flag
""")
    if option == "1":
        if outputs_left > 0:
            output = next(rng)
            print(output)
            outputs_left-=1
        else:
            print("You know too much!")
    elif option == "2":
        print("Prove you know the flag!")
        print("Whats a?")
        if str(a) != input():
            continue
        print("Whats c?")
        if str(c) != input():
            continue
        print("Ok, you must know the flag then... here it is:")
        print(FLAG)
        quit()
    else:
        quit()

{% endccb %}

Contrary to the description, this challenge is not about "Local Consultative Group"s, but rather the other LCG, Linear Congruential Generators. An LCG is an algorithm that produces pseudo-random integers from a certain range. The way it works is following a recurrence relation.

1. Choose a modulus {% katex %} m {% endkatex %}.
2. Choose three integers {% katex %} 0 < a, x_0, c < m {% endkatex %}

Using these, we generate a pseudo-random sequence of integers {% katex %} 0 \leq x_1, x_2, \cdots < m {% endkatex %} with the following relation:

{% katex '{ "displayMode": true }' %}
x_{n+1} = a x_n + c \pmod{m}
{% endkatex %}  