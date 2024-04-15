---
title: omniscient-larry
date: 2024-04-15
tags: 
- algo
- author-squiddy
categories: AmateursCTF 2024
---

written by {% person squiddy %}

> Another problem :sob: Can you help?
> `nc chal.amt.rs 1411`
> Don't forget to orz the omniscient larry!

# The Problem

As with all the algo problems in this CTF, the challenge is to analyze their given solution in `lib.rs` and optimize it.
We're also given the testcase generator, `gen.rs`, and the `nc` server code, in `main.rs`.

<details>
<summary><code>lib.rs</code>, their solution</summary>
```rust
pub const MOD: u32 = 1e9 as u32 + 9;

pub mod gen;
pub mod omniscient_god;

pub fn validate_string(s: &str) {
    for c in s.chars() {
        // orz larry
        assert!("ozly".contains(c));
    }
}

pub mod my_code {
    use super::{validate_string, MOD};
    use std::collections::HashSet;

    struct Solver {
        str: Vec<u8>,
        vis: HashSet<Vec<u8>>,
        ans: u32,
    }

    impl Solver {
        fn solve(s: String) -> u32 {
            validate_string(&s);

            let mut solver = Self {
                str: s.into_bytes(),
                vis: HashSet::new(),
                ans: 0,
            };
            solver.str.sort_unstable();

            for &c in b"ozly" {
                solver.dfs(vec![c]);
            }

            solver.ans
        }

        fn dfs(&mut self, mut s: Vec<u8>) {
            if !self.vis.insert(s.clone()) {
                return;
            } else if s.len() == self.str.len() {
                // check s is a permutation of `self.str`
                s.sort_unstable();

                if s == self.str {
                    self.ans = (self.ans + 1) % MOD;
                }
                return;
            }

            for i in 0..s.len() {
                // perform an expansion - replace s[i] with some 2 character string
                let expansions = match s[i] {
                    b'o' => [b"lo", b"oy"],
                    b'z' => [b"yz", b"zl"],
                    b'l' => [b"ll", b"oz"],
                    b'y' => [b"yy", b"zo"],
                    _ => unreachable!(),
                };

                for expansion in expansions {
                    let mut next = s.clone();
                    next.splice(i..=i, expansion.iter().copied());

                    self.dfs(next);
                }
            }
        }
    }

    pub fn solve(s: &str) -> u32 {
        Solver::solve(s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// verify my brute force by comparing against the omniscient god
    #[test]
    fn stress_test() {
        let mut rng = rand::thread_rng();

        for _ in 0..1000 {
            let s = gen::rand_string(&mut rng, 1, 10);

            assert_eq!(my_code::solve(&s), omniscient_god::solve(&s));
        }
    }
}
```
</details>

<details>
<summary><code>gen.rs</code>, testcase generator</summary>
```rust
use rand::prelude::*;

pub fn rand_string(rng: &mut impl Rng, min_n: usize, max_n: usize) -> String {
    let n = rng.gen_range(min_n..=max_n);

    let mut arr = vec![];

    {
        let m = rng.gen_range(n / 4..=3 * n / 4);
        let mut o = m / 2;
        let mut z = m - o;

        if rng.gen::<bool>() {
            std::mem::swap(&mut o, &mut z);
        }

        arr.extend(std::iter::repeat('o').take(o));
        arr.extend(std::iter::repeat('z').take(z));
    }

    while arr.len() < n {
        arr.push(if rng.gen::<bool>() { 'l' } else { 'y' });
    }

    arr.shuffle(rng);

    arr.into_iter().collect()
}
```
</details>

<details>
<summary><code>main.rs</code>, <code>nc</code> server</summary>
```rust
use omniscient_larry::{gen, omniscient_god};
use std::io::{self, BufRead, BufWriter, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut stdin = io::stdin().lock();

    let mut rng = rand::thread_rng();
    let mut queries = vec![];

    queries.push(gen::rand_string(&mut rng, 9e4 as usize, 1e5 as usize));
    for _ in 0..100 {
        queries.push(gen::rand_string(&mut rng, 1, 1000));
    }

    let mut out = BufWriter::new(io::stdout().lock());
    writeln!(out, "{}", queries.len())?;
    for s in &queries {
        writeln!(out, "{s}")?;
    }
    out.flush()?;

    for s in &queries {
        omniscient_larry::validate_string(s);

        let ans = omniscient_god::solve(s);
        let mut your_ans = String::new();
        stdin.read_line(&mut your_ans)?;

        if ans.to_string() != your_ans.trim() {
            panic!("the omniscient god disagrees - maybe you should worship him more?");
        }
    }

    println!(
        "Yay! Good job, here's your flag and remember to orz larry: {}",
        std::fs::read_to_string("./flag.txt")?
    );

    Ok(())
}
```
</details>

I can't compile Rust, so I'll translate their solution and the testcase generator into Python:

```py
MOD = 1_000_000_009

# s is a string of "o", "z", "l" and "y"

exps = {
    "o": ["lo", "oy"],
    "z": ["yz", "zl"],
    "l": ["ll", "oz"],
    "y": ["yy", "zo"]
}

def provided_solver(s):
    cstr = list(s)
    vis = set()
    ans = 0

    cstr.sort()
    cstr = ''.join(cstr)

    def dfs(moves):
        nonlocal ans
        if (''.join(moves) in vis):
            return
        vis.add(''.join(moves))
        if len(moves) == len(cstr):
            if cstr == ''.join(sorted(moves)):
                ans += 1
                ans %= MOD
            return

        for i in range(len(moves)):
            expansions = exps[moves[i]]
            for expansion in expansions:
                nextmoves = moves[:i] + list(expansion) + moves[(i+1):]
                dfs(nextmoves)

    for c in "olzy":
        dfs([c])

    return ans

import random

def gen(min_n, max_n):
    n = random.randint(min_n, max_n)
    # note the special nature of this gen function
    m = random.randint(n // 4, (3 * n) // 4)
    o = m // 2
    z = m - o

    if random.randint(0, 1):
        o, z = z, o

    arr = "o" * o + "z" * z

    while len(arr) < n:
        arr += ("l" if random.randint(0, 1) else "y")

    arr = list(arr)
    random.shuffle(arr)
    arr = ''.join(arr)

    return arr
```

Much better. 

## Analysing the given solution
So, what does the solution do?

Basically, we're provided a string $S$ of length $1 \le N \le 100000$ (from the `nc` code), containing only characters `o`, `z`, `l` or `y`. The provided code tries to reach any ***permutation*** of $S$ by following these steps:
1. Start from a string $S'$, either `"o"`, `"l"`, `"z"` or `"y"`.
2. Replace a character in $S'$ with one of its possible expansions.
  - `o` -> `lo` or `oy`
  - `z` -> `yz` or `zl`
  - `l` -> `ll` or `oz`
  - `y` -> `yy` or `zo`
3. Repeat step 2 until $S'$ is of length $N$. 
4. Count how many unique permutations of $S$ that $S'$ can be.

As someone with algorithm experience, this is quite inefficient. The big O time complexity is exponential, on the order of $O(2^N)$! This means it's only good for $N \le 30$ or so; $N = 100000$ would take $~10^{30,000}$ years! We can do *much* better.

<hr />
<details>
<summary>This algorithm's time complexity</summary>
We start with 4 states, <code>"o"</code>, <code>"z"</code>, <code>"l"</code> or <code>"y"</code>.<br />
At each state, we can expand it to 2 states, and we do this for each character in the string.<br />
So, if we let $s(i)$ be the number of states with length $i$, then $s(i + 1) = 2^i \cdot s(i)$ for $i \ge 1$. $s(1) = 4$.<br />
<i>However</i>, because we use a visited array, $s(i)$ is actually bounded by $4^N$ (which is how many possible strings of length $N$ there are containing only <code>olzy</code>).<br /><br />
The code explores all states until length $N$, so the time complexity is (roughly)<br />
$\begin{aligned}
\sum_{i=1}^{N}s(i) &= 4 + 2 * (4) + 4 * (2 * 4) + 4^4 + 4^5 + \ldots\\
&\approx (4^0 + 4^1 + 4^2 + 4^3 + \ldots)\\
&= O(4^N)
\end{aligned}
$<br /><br />
Practically, though, many of these states are not reachable. Printing the length of the visited set for $N = 15$, we get $\sum_{i=1}^{15}s(i) = 131,068$, much smaller than $4^{15} = 1,073,741,824$.<br /><br />
Empirically, printing out $\sum_{i=1}^{n}s(i)$ for $1 \le n \le 17$, we see it's more on the order of $O(2^N)$.
<div style="display:flex;justify-content:center;align-items:center;flex-direction:column;">
<table style="width:fit-content;">
<thead>
<tr>
<th>$n$</th>
<th>$\sum_{i=1}^{n}s(i)$</th>
<th>Ratio</th>
</tr>
</thead>
<tbody>
<tr>
<td>1</td>
<td>4</td>
<td>-</td>
</tr>
<tr>
<td>2</td>
<td>12</td>
<td>$\frac{12}{4}=3$</td>
</tr>
<tr>
<td>3</td>
<td>28</td>
<td>$\frac{28}{12}=2.333$</td>
</tr>
<tr>
<td>4</td>
<td>60</td>
<td>$\frac{60}{28}=2.143$</td>
</tr>
<tr>
<td>5</td>
<td>124</td>
<td>$\frac{124}{60}=2.067$</td>
</tr>
<tr>
<td>6</td>
<td>252</td>
<td>$\frac{252}{124}=2.032$</td>
</tr>
<tr>
<td>7</td>
<td>508</td>
<td>$\frac{508}{252}=2.016$</td>
</tr>
<tr>
<td>8</td>
<td>1020</td>
<td>$\frac{1020}{508}=2.008$</td>
</tr>
<tr>
<td>9</td>
<td>2044</td>
<td>$\frac{2044}{1020}=2.004$</td>
</tr>
<tr>
<td>10</td>
<td>4092</td>
<td>$\frac{4092}{2044}=2.002$</td>
</tr>
<tr>
<td>11</td>
<td>8188</td>
<td>$\frac{8188}{4092}=2.001$</td>
</tr>
<tr>
<td>12</td>
<td>16380</td>
<td>$\frac{16380}{8188}=2.0004$</td>
</tr>
<tr>
<td>13</td>
<td>32764</td>
<td>$\frac{32764}{16380}=2.0002$</td>
</tr>
<tr>
<td>14</td>
<td>65532</td>
<td>$\frac{65532}{32764}=2.0001$</td>
</tr>
<tr>
<td>15</td>
<td>131068</td>
<td>$\frac{131068}{65532}=2.00006$</td>
</tr>
<tr>
<td>16</td>
<td>262140</td>
<td>$\frac{262140}{131068}=2.00003$</td>
</tr>
<tr>
<td>17</td>
<td>524284</td>
<td>$\frac{524284}{262140}=2.00001$</td>
</tr>
</tbody>
</table>
</div>
<br />
The reason for this has to do with the solution to this challenge itself, presented later, which allows us to get a better estimate of the upper bound of $s(i)$.<br />
This analysis also ignores the time complexity of set insertion, which in the case of Python, is $O(1)$, but may be $O(\log N)$ in other languages, giving us a final time complexity of $O(2^N\log N)$ in those cases.<br />
Space complexity is just the size of the visited set, which is $O(2^N)$, plus some negligible $O(N)$ space for the depth first search.
</details>
<details>
<summary>How long $N=100000$ would take</summary>
<div style="text-align:center">
\[
2^{100000} = 10^{\log{(2^{100000})}}\\
\log{(2^{100000})} = 100000 \cdot \log{2} \approx 30103
\]
</div>
At $10^9$ operations per second, with $10^7$ seconds in a year, it would take $10^{30103 - 9 - 7} = 10^{30087}$ years to complete.<br />
</details>
<hr />

## `o` and `z`

First, notice that the number of `o`s and `z`s differs by at most 1 only. This is because `l` and `y` both create both `o` and `z` in equal numbers; starting from `l` or `y` leads only to strings with the same number of `o`s and `z`s. The only way to get a string with a different number of `o`s and `z`s is to start from `o` or `z`. `o` and `z` are thus specially constrained.

Secondly, as we are working with *permutations* of $S$, we can simply count how many of each character there are in $S$. A string $S'$ is only a valid permutation of $S$ if it has the same number of `o`s, `z`s, `l`s and `y`s as $S$. From now, I will refer to these counts as $o$, $z$, $l$ and $y$.

Let's work backwards instead of forwards. Given a permutation of $S$, is it possible to reach either `"o"`, `"l"`, `"z"` or `"y"` by performing the operations in reverse order?

Our operations are now:
- `lo` or `oy` -> `o`
- `yz` or `zl` -> `z`
- `ll` or `oz` -> `l`
- `yy` or `zo` -> `y`

Let's explore some permutations of only `o` and `z`, and see if they can be decomposed.
- `ozoz` -> `ll` -> `l`
- `zozo` -> `yy` -> `y`
- `oozz` -> `olz`
- `zzoo` -> `zyo`
- `ozzo` -> `ly`

It seems that the only valid permutations of only `o` and `z` must follow an alternating pattern `ozozoz...` or `zozozo...`. Any `oo` or `zz` causes the permutation to not be decomposable.
If $o>z$, it follows that only `ozozozo...` is possible, and vice versa. If $o=z$, both are possible.

## `l` and `y`
Let's then explore how to insert `l` and `y` into this "backbone" of `o` and `z`. 

We can insert `l` in front of an `o` or behind a `z`, and `y` in front of a `z` or behind an `o`. We can, of course, insert multiple `l`s or `y`s in a row, as they will simply be reduced to single characters via `ll` -> `l` and `yy` -> `y`.

For example, for the `ozo` permutation, we can place an `l` in 2 places, and a `y` in 2 places, like so:

{% ccb html:true %}<span class='code-segment-highlight'>l</span>o<span class='code-segment-highlight'>y</span>z<span class='code-segment-highlight'>l</span>o<span class='code-segment-highlight'>y</span>{% endccb %}

In fact, it turns out that for every case where $o \neq z$, there are $\max{(o,z)}$ places to put both `l` and `y`.

For the $o=z$ case, it's based on which permutation we use:
- `ozozoz...`: $o+1$ places for `l`, $o$ places for `y`
- `zozozo...`: $o$ places for `l`, $o+1$ places for `y`

## Stars and bars

If we have $l$ `l`s, and $p_l$ places for `l`s, as determined from above, how many ways are there to insert the `l`s?
Turns out, this is a standard combinations problem, solved with the [stars and bars](https://en.wikipedia.org/wiki/Stars_and_bars_(combinatorics)) method. The answer is 
<div style="text-align:center">$\begin{aligned}
\frac{(l+p_l-1)!}{(l!)((p_l-1)!)} = \binom{l+p_l-1}{l}
\end{aligned}$</div>
<hr />
<details>
<summary>Stars and bars derivation</summary>
Let's represent the <code>l</code>s with <code>*</code>s.<br />
We want to partition these <code>*</code>s into $p_l$ groups, so let us create $p_l-1$ dividers, <code>|</code>s.<br />
We can then represent any combination of <code>l</code>s in these groups as a string of $l$ <code>*</code>s and $p_l-1$ <code>|</code>s, like this permutation:
<div style="text-align:center">
<code>**|***|**</code>
</div>
which signifies 2 <code>l</code>s in the first group, 3 in the second, and 2 in the third.<br /><br />
Importantly, (i) any permutation of this string is a valid arrangement, and (ii) no two permutations of this string correspond to the same arrangement.<br />
Thus, the number of ways to partition the <code>l</code>s is just the <i>number of permutations of this string</i>.<br />
The number of permutations of a string of $l$ identical <code>*</code>s and $p_l-1$ identical <code>|</code>s is $\frac{(l+p_l-1)!}{l!(p_l-1)!}$, which is the formula above.
</details>
<hr />

Similarly, for $y$ `y`s, and $p_y$ places for `y`s, the number of ways to insert the `y`s is $\binom{y+p_y-1}{y}$.

## Putting it together

Now, we have $l$ `l`s, and $y$ `y`s, and we have to find the number of ways to insert them into the `oz` backbone.

We simply combine our previous results:
- If $o>z$ or $o<z$, we have $p_l$ = $p_y$ = $\max{(o,z)}$. We can only use 1 of the 2 backbones, `oz...zo` only for $o>z$, and `zo...oz` only for $z>o$. Thus, the number of permutations of $S$ that we can make is $\binom{l+p_l-1}{l} \cdot \binom{y+p_y-1}{y}$.
- If $o=z$, we have 2 cases:
  - If we use `oz...oz`, then $p_l = o+1$, $p_y = o$. The number of permutations is $\binom{l+p_l-1}{l} \cdot \binom{y+p_y-1}{y} = \binom{l+o}{l} \cdot \binom{y+o-1}{y}$.
  - If we use `zo...zo`, then $p_l = o$, $p_y = o+1$. The number of permutations is $\binom{l+p_l-1}{l} \cdot \binom{y+p_y-1}{y} = \binom{l+o-1}{l} \cdot \binom{y+o}{y}$.
  - The total number of permutations we can make is the sum of these two cases.

We can even see this from the output of the provided solution. With the testcase $S$=`oozllyy`, and printing the moves just before they are placed in the visited array, these are the permutations we get:
{% ccb html:true %}
<span class='code-segment-highlight'>o</span>yy<span class='code-segment-highlight'>z</span>ll<span class='code-segment-highlight'>o</span>
<span class='code-segment-highlight'>o</span>y<span class='code-segment-highlight'>z</span>ll<span class='code-segment-highlight'>o</span>y
<span class='code-segment-highlight'>o</span><span class='code-segment-highlight'>z</span>ll<span class='code-segment-highlight'>o</span>yy
l<span class='code-segment-highlight'>o</span>yy<span class='code-segment-highlight'>z</span>l<span class='code-segment-highlight'>o</span>
l<span class='code-segment-highlight'>o</span>y<span class='code-segment-highlight'>z</span>l<span class='code-segment-highlight'>o</span>y
l<span class='code-segment-highlight'>o</span><span class='code-segment-highlight'>z</span>l<span class='code-segment-highlight'>o</span>yy
ll<span class='code-segment-highlight'>o</span>yy<span class='code-segment-highlight'>z</span><span class='code-segment-highlight'>o</span>
ll<span class='code-segment-highlight'>o</span>y<span class='code-segment-highlight'>z</span><span class='code-segment-highlight'>o</span>y
ll<span class='code-segment-highlight'>o</span><span class='code-segment-highlight'>z</span><span class='code-segment-highlight'>o</span>yy
{% endccb %}
The `ozo` backbone has been highlighted, and note how the `l`s and the `y`s "drift" through their respective allowed boxes.

We then code a (slightly sus) solution in Python:
```py
MOD = 1_000_000_009

fact_cache = [1, 1] + [0] * 200000
last_max_run = 1

def factorial(n):
    global last_max_run
    for i in range(last_max_run, n):
        fact_cache[i + 1] = (i + 1) * fact_cache[i]
    last_max_run = max(last_max_run, n)
    return fact_cache[n]

def solver(s):
    o_ct = 0
    z_ct = 0
    l_ct = 0
    y_ct = 0
    ans = 0
    for i in s:
        if i == 'o':
            o_ct += 1
        if i == 'z':
            z_ct += 1
        if i == 'l':
            l_ct += 1
        if i == 'y':
            y_ct += 1
    has_extra = (o_ct != z_ct)

    if has_extra:
        barr = max(o_ct, z_ct) - 1

        # stars and bars
        y_ans = (factorial(y_ct + barr) * pow(factorial(barr), -1, MOD) * pow(factorial(y_ct), -1, MOD)) % MOD
        l_ans = (factorial(l_ct + barr) * pow(factorial(barr), -1, MOD) * pow(factorial(l_ct), -1, MOD)) % MOD
        return (y_ans * l_ans) % MOD
    else:
        # symmetry breaks a little
        barr_y = o_ct - 1
        barr_l = o_ct

        y_ans = (factorial(y_ct + barr_y) * pow(factorial(barr_y), -1, MOD) * pow(factorial(y_ct), -1, MOD)) % MOD
        l_ans = (factorial(l_ct + barr_l) * pow(factorial(barr_l), -1, MOD) * pow(factorial(l_ct), -1, MOD)) % MOD
        ans += (y_ans * l_ans) % MOD

        barr_l, barr_y = barr_y, barr_l

        y_ans = (factorial(y_ct + barr_y) * pow(factorial(barr_y), -1, MOD) * pow(factorial(y_ct), -1, MOD)) % MOD
        l_ans = (factorial(l_ct + barr_l) * pow(factorial(barr_l), -1, MOD) * pow(factorial(l_ct), -1, MOD)) % MOD
        ans += (y_ans * l_ans) % MOD

        return ans % MOD

# driver
from pwn import *
from tqdm import tqdm
conn = remote("chal.amt.rs", 1411)
N = int(conn.recvline().decode().strip())
strs = []
for _ in tqdm(range(N)):
    strs.append(conn.recvline().decode().strip())
for strr in tqdm(strs):
    conn.sendline(str(solver(strr)))
print(conn.recv())
```

> Yay! Good job, here's your flag and remember to orz larry: amateursCTF{orz-larry-how-is-larry-so-orz-5318bfae97e201a66dc12069058e1b11d971ac7b24a8c87b2aec826dd39098d4}

The time complexity of this solution is $O(N)$, to read in the string $S$, and to compute $N!$. The space complexity is $O(N)$ because we store the factorials (and the string $S$, technically).
<hr />
<details>
<summary>Bonus: Re-examining the time complexity (warning: <b><i>math</i></b>)</summary>
Let's recalculate $s(n)$ more accurately, using the combinatoric solution we've found.<br /><br />
First, let's write $s(n)$ = $\sum_{i=1}^{n}bb(n, i)$, where $bb(n, i)$ represents the number of states of total length $n$ with an <code>oz</code> backbone of length $i$.<br />
$bb(n, i)$ can be split into 2 behaviours, odd $i$ and even $i$.<br /><br />
For odd $i$, either $o>z$ or $o \lt z$. Either way, $p_l=p_y=\max{(o,z)}=\frac{i+1}{2}$. Let $l$ be the number of <code>l</code>s in the state. $i+l+y=n$, so $y=n-i-l$.<br />
\[\begin{aligned}
    bb(n,i) &= 2\cdot\sum_{l=0}^{n-i}\binom{l+\frac{i+1}{2}-1}{l}\binom{n-i-l+\frac{i+1}{2}-1}{n-i-l}\\
    &= 2\cdot\sum_{l=0}^{n-i}\binom{l+\frac{i-1}{2} }{\frac{i-1}{2} }\binom{n-i-l+\frac{i-1}{2} }{\frac{i-1}{2} }\\
    &= 2\cdot\sum_{l=\frac{i-1}{2} }^{n-\frac{i+1}{2} }\binom{l}{\frac{i-1}{2} }\binom{n-1-l}{\frac{i-1}{2} }\\
    &= 2\cdot\left(\sum_{l=0 }^{n-1 }\binom{l}{\frac{i-1}{2} }\binom{n-1-l}{\frac{i-1}{2} } - \sum_{l=0 }^{\frac{i-3}{2} }\binom{l}{\frac{i-1}{2} }\binom{n-1-l}{\frac{i-1}{2} } - \sum_{l=n-\frac{i-1}{2} }^{n-1}\binom{l}{\frac{i-1}{2} }\binom{n-1-l}{\frac{i-1}{2} }\right)\\
    &= 2\cdot\left(\sum_{l=0 }^{n-1 }\binom{l}{\frac{i-1}{2} }\binom{n-1-l}{\frac{i-1}{2} } - 2 \cdot \sum_{l=0 }^{\frac{i-3}{2} }\binom{l}{\frac{i-1}{2} }\binom{n-1-l}{\frac{i-1}{2} }\right)\\
    &= 2\cdot\left(\binom{n}{i} - 2 \cdot \sum_{l=0 }^{\frac{i-3}{2} }\binom{l}{\frac{i-1}{2} }\binom{n-1-l}{\frac{i-1}{2} }\right) \text{[Chu-Vandermonde Identity]}\\
\end{aligned}\]
Note, however, that from $l=0$ to $\frac{i-3}{2}$, the summand is 0, as $\binom{l}{\frac{i-1}{2} }=0$ for $l<\frac{i-1}{2}$.<br />
Thus, precisely, $bb(n,i) = 2\cdot\binom{n}{i}$ for odd $i$.<br /><br />
For even $i$, $o=z$. Let $l$ be the number of <code>l</code>s in the state. There are 2 cases, one where $p_l=\frac{i}{2}$ and $p_y=\frac{i}{2}+1$, and where $p_l=\frac{i}{2}+1$ and $p_y=\frac{i}{2}$. $y=n-i-l$ still.<br />
\[\begin{aligned}
    bb(n,i) &= \sum_{l=0}^{n-i}\binom{l+\frac{i}{2} }{l}\binom{n-i-l+\frac{i}{2}-1}{n-i-l} + \sum_{l=0}^{n-i}\binom{l+\frac{i}{2}-1 }{l}\binom{n-i-l+\frac{i}{2} }{n-i-l}\\
    &= \sum_{l=0}^{n-i}\binom{l+\frac{i}{2} }{\frac{i}{2} }\binom{n-i-l+\frac{i}{2}-1}{\frac{i}{2}-1} + \sum_{l=0}^{n-i}\binom{l+\frac{i}{2}-1 }{\frac{i}{2}-1}\binom{n-i-l+\frac{i}{2} }{\frac{i}{2} }\\
    &= 2\cdot\binom{n}{i} - \sum_{l=0}^{\frac{i}{2}-1}\binom{l}{\frac{i}{2} }\binom{n-1-l}{\frac{i}{2}-1} - \sum_{l=n-\frac{i}{2}+1}^{n-1}\binom{l}{\frac{i}{2} }\binom{n-1-l}{\frac{i}{2}-1} - \sum_{l=0}^{\frac{i}{2}-3}\binom{l}{\frac{i}{2}-1 }\binom{n-1-l}{\frac{i}{2} } - \sum_{l=n-\frac{i}{2} }^{n-1}\binom{l}{\frac{i}{2}-1 }\binom{n-1-l}{\frac{i}{2} }\\
    &= 2\cdot\binom{n}{i}
\end{aligned}\]
So, as it turns out, $bb(n,i) = 2\cdot\binom{n}{i}$ for all $i$.<br /><br />
Then, 
\[\begin{aligned}
    s(n) &= \sum_{i=0}^{n}bb(n, i)\\
    &= \sum_{i=0}^{n}2\cdot\binom{n}{i}\\
    &= 2 \cdot \sum_{i=0}^{n}\binom{n}{i}\\
    &= 2 \cdot 2^n\\
    &= 2^{n+1}
\end{aligned}\]
Thus, the total states $S(N)$ for some string length $N$ is then
\[\begin{aligned}
    S(N) &= \sum_{n=1}^{N}s(n)\\
    &= \sum_{n=2}^{N+1}2^n\\
    &= 2^{N+2}-4\\
    &= O(2^N)
\end{aligned}\]
which is exactly what we got from the empirical analysis (try it yourself!)<br />
<div style="display:flex;justify-content:center;align-items:center;flex-direction:column;">
<table style="width:fit-content;">
<thead>
<tr>
<th>$n$</th>
<th>$\sum_{i=1}^{n}s(i)$</th>
<th>Ratio</th>
</tr>
</thead>
<tbody>
<tr>
<td>17</td>
<td>524284</td>
<td>$\frac{524284}{262140}=2.00001$</td>
</tr>
</tbody>
</table>
</div>
\[S(17) = 2^{19} - 4 = 524284\]<br />
Thus, the time complexity is indeed $O(2^N)$!
</details>
<hr />
