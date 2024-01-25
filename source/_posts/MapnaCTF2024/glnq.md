---
title: GLNQ
date: 2024-01-24
tags: 
- crypto
- author-tomato
categories: MapnaCTF 2024
---

solved by {% person tomato %}

> Solving the DLP in matrices over a finite field is no trivial task. What are your thoughts on this GLNQ belief? 
> Note: flag = MAPNA{m}, Don't convert m to bytes.

DISCLAIMER: My solution to this challenge involves heavy trolling and is much more complex than required.

{% ccb caption:glnq.sage
lang:py
gutter1:1-18%}

#!/usr/bin/env sage

from Crypto.Util.number import *
from flag import flag

F, k = GF(2**8), 14

while True:
	G = random_matrix(F, k)
	if G.is_invertible():
		break

flag = flag.lstrip(b'MAPNA{').rstrip(b'}')
m = bytes_to_long(flag)
H = G ** m

print(f'G = {G}')
print(f'H = {H}')

{% endccb %}

We are given a code snippet which generates a random 14 by 14 (invertible) matrix `G` under GF(2^8). Then, it gives us both `G` and `G^m`, and we have to recover m. Essentially, DLP on matrices under GF(2^8).

## Jordan normal form

When you think of raising a matrix to a power, you may think of one of the basic topics of linear algebra, diagonalization. If a diagonalizable {%katex%}n \times n{%endkatex%} matrix {%katex%}A{%endkatex%} has {%katex%}n{%endkatex%} eigenvalues {%katex%}\lambda_1, \lambda_2, \ldots, \lambda_n{%endkatex%}, then one such diagonalization could be:

{% katex '{ "displayMode": true }' %}
P^{-1}AP = D = \begin{bmatrix}
\lambda_1 & & &\\
& \lambda_2 & &\\
& & \ddots &\\
& & & \lambda_n\\
\end{bmatrix}
{% endkatex %}

and equivalently

{% katex '{ "displayMode": true }' %}
A = PDP^{-1}
{% endkatex %}

This is useful, as if you wanted to raise the matrix {%katex%}A{%endkatex%} to the {%katex%}k{%endkatex%}th power, you could do it by raising {%katex%}D{%endkatex%} to the {%katex%}k{%endkatex%}th power, which is much easier as it is diagonal:

{% katex '{ "displayMode": true }' %}
A^k = PD^k P^{-1} = P\begin{bmatrix}
\lambda_1^k & & &\\
& \lambda_2^k & &\\
& & \ddots &\\
& & & \lambda_n^k\\
\end{bmatrix}P^{-1}
{% endkatex %}

(this would make discrete log simpler as you can consider the discrete log of the elements of the matrix instead of the entire matrix). But, not all matrices are diagonalizable. We can check this:
```py
G.is_diagonalizable()
# False
```

So, we instead use the matrix's Jordan normal form. The Jordan normal form is an alternative for non-diagonalizable matrices, which is <u>almost</u> diagonal:

{% katex '{ "displayMode": true }' %}
P^{-1}AP = J = \begin{bmatrix}
J_1 & & &\\
& J_2 & &\\
& & \ddots &\\
& & & J_m\\
\end{bmatrix}
{% endkatex %}

where each {%katex%}J_i{%endkatex%} is a <u>jordan block</u> of the form:

{% katex '{ "displayMode": true }' %}
J_i = \begin{bmatrix}
\lambda_i &1 & &\\
& \lambda_i &\ddots &\\
& & \ddots &1\\
& & & \lambda_i\\
\end{bmatrix}
{% endkatex %}

So, raising {%katex%}A{%endkatex%} to the {%katex%}k{%endkatex%}th power would now require raising the Jordan blocks to the {%katex%}k{%endkatex%}th power, which are much easier to deal with than the entire matrix. Sage has a builtin method to calculate Jordan normal, so we can just use it:

```py
G.jordan_form()
# RuntimeError: Some eigenvalue does not exist in Finite Field in z8 of size 2^8.
```

Right.. the Jordan normal form still requires all the eigenvalues to exist (but not necessarily be distinct). In order to force the eigenvalues to exist, we need to extend the field we are working on, which is GF(2^8). To find the field we need to extend to (with sage API), we can first consider the characteristic polynomial of {%katex%}G{%endkatex%}, which is a monic polynomial whose roots are the eigenvalues of {%katex%}G{%endkatex%}. Then, we find the splitting field of this polynomial, which is the smallest field extension over which such a polynomial completely factorizes into linear factors, meaning that it would have 14 real roots aka 14 real eigenvalues in our case.

With this, we are able to find the Jordan normal form of {%katex%}G{%endkatex%}:

```py
chG = G.charpoly()
K.<a> = chG.splitting_field()
_G = Matrix(K, G)
JG, P = _G.jordan_form(transformation=true)
```

Now, we can try doing discrete log on the Jordan blocks of `J`. We compute {%katex%}J^m = P^{-1}A^mP{%endkatex%} and do discrete log: (since J happens to be diagonal we can just index it).

```py
JH = ~P*H*P
print([discrete_log(JH[i][i],JG[i][i]) for i in range(14)])
```

gives `[7393434767644474031, 7393434767644474031, 7393434767644474031, 7393434767644474031, 7393434767644474031, 235852996149746, 235852996149746, 235852996149746, 235852996149746, 7393434767644474031, 235852996149746, 7393434767644474031, 7393434767644474031, 235852996149746]`. 

Notice that not all of these values are the same. This is because the Jordan blocks do not necessarily have the same multiplicative order as the original matrix, and may have lower orders. If {%katex%}k_1, k_2{%endkatex%} are different powers we obtain from taking the discrete log of Jordan blocks, we would have:

{% katex '{ "displayMode": true }' %}
J_{1G}^m = J_{1G}^{k_1} = J_{1H}\\
J_{2G}^m = J_{2G}^{k_2} = J_{2H}
{% endkatex %}

which implies that

{% katex '{ "displayMode": true }' %}
m \equiv k_1 \pmod {\text{ord}(J_{1G})}\\
m \equiv k_2 \pmod {\text{ord}(J_{2G})}
{% endkatex %}

meaning that we can still recover {%katex%}m{%endkatex%} with the Chinese remainder theorem, provided that {%katex%}\text{ord}(G) \mid \text{lcm}(\text{ord}(J_{1G}), \text{ord}(J_{2G}), \ldots, \text{ord}(J_{14G})){%endkatex%}. Lucky for us, {%katex%}\text{ord}(G){%endkatex%} is actually equal to the lcm, otherwise we would have to do a bit of guesswork. 

The reason that finding the Jordan normal form happens to work well here is that our Jordan blocks have multiplicative orders that are much lower than the original multiplicative order, allowing for the discrete log to be much easier to compute now. (this does not always happen)

## Full sage implementation

```py
GGG, HHH = open("./glnq_9c3935a6c97ee38b4ba28e28da342b26ac13b45a/glnq/output.txt").read().lstrip("G = ").split("H = ")
from sage.misc.parser import Parser
z8 = var("z8")
p = Parser(make_var={"z8":z8})

R.<x> = PolynomialRing(GF(2),'x')

def num2poly(num):
    return sum(int(j)*x^i for i,j in enumerate(bin(num)[2:][::-1]))

def poly2num(poly):
    if poly==0:
        return 0
    else:
        return int("".join(map(str, poly.list()))[::-1],2)

GG = [[num2poly(poly2num(p.parse(i.lstrip("[").rstrip("]")[49*x:49*(x+1)]))) for x in range(14)] for i in GGG.strip().split("\n")]
HH = [[num2poly(poly2num(p.parse(i.lstrip("[").rstrip("]")[42*x:42*(x+1)]))) for x in range(14)] for i in HHH.strip().split("\n")]

G = Matrix(GF(2^8), GG)
H = Matrix(GF(2^8), HH)

# Finished parsing matrices

chG = G.charpoly()
K.<a> = chG.splitting_field()
_G = Matrix(K, G)
JG, P = _G.jordan_form(transformation=true)
JH = ~P*H*P

assert JG.is_diagonal()
powers = [discrete_log(JH[i][i],JG[i][i]) for i in range(14)]
orders = [JG[i][i].multiplicative_order() for i in range(14)]
assert G.multiplicative_order() == lcm(orders)
m = crt(powers, orders)
assert G^m == H
print(f"MAPNA{{{m}}}")
```

giving the flag `MAPNA{6424379811053277573417442136}`.

### Simpler solution

I was a complete bozo when solving this, and there is a miles simpler solution which I found out about in discord. Although `discrete_log(H, G)` seems to error out,

```py
discrete_log(H, G, algorithm="lambda")
```

solves the entire challenge in a few seconds. Simply a misstep on my end to have not tried all the `discrete_log` algorithms at the start, because seeing the solve count I didn't think to try. Sage API is too powerful... at least I learned a bit about linear algebra because of this challenge though

Note: the name of the challenge GLNQ seems to lead to this [paper](https://uwaterloo.ca/scholar/sites/ca.scholar/files/ajmeneze/files/glnq.pdf), although understanding the algorithm described there was really difficult and I sank too much time into this route.