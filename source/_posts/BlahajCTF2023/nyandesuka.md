---
title: Nyandesuka??
date: 2023-12-06
tags: rev
categories: BlahajCTF 2023
---

solved by {% person treeindustry %}

> People told me to make my code more accessible, so I decided to make my latest project in Scratch! Check it out: https://scratch.mit.edu/projects/851085916/

# Notes

This challenge was originally at https://scratch.mit.edu/projects/845244451/ but was made simpler so people would solve it.

Also, please forgive my poor paint skills

# Code

Sprite code:

![Tells you whether you won](/static/BlahajCTF2023/nyan_1.PNG)

Nothing much to see here.

The stage code has 4 segments, the first segment is the initial setup:

![Get input and init variables](/static/BlahajCTF2023/nyan_2.PNG)

Notable variables:

+ sp is `1020`
- STACK has 1024 `0`s (.rodata has nothing)
- Label Stack and TTY are initially empty

`getchar` gets the value from the next character from our input based on ascii:

![](/static/BlahajCTF2023/nyan_3.PNG)

`index_of` is the index of a character in a string:

![](/static/BlahajCTF2023/nyan_4.PNG)

Then we have the main segment which is the code we have to reverse engineer:

![main segment of code, quite long](/static/BlahajCTF2023/nyan_5.PNG)

Not mentioned is `putchar`, which just outputs a character.

# Strategy

Read the code and step through it

# Observations

`Label Stack` is never used.

`winning` needs to be 4 for us to solve the challenge.

Item `sp + 4` (which is 1024) of `STACK` is accessed in many of the `if` blocks:
+ First, it is set to 4
- If it is greater than 0, it decreases by 1 every iteration
- If it is 0, the program exits
- Different blocks are run if it is 4, 3, 2 or 1, and `winning` can only be increased in one of these blocks

Every iteration, `getchar` is called 3 times.

# Values in the stack

Items `sp  +  3` (1023) to `sp - 10` (1010) are only modified once per iteration. Let the values of the 3 characters from our input be x, y and z respectively. The values in the stack are:

| Item | Code | Value |
| --- | --- | --- |
| 1023 | `replace item sp+3 of STACK with return value` | x |
| 1022 | `replace item sp+2 of STACK with return value` | y |
| 1021 | `replace item sp+1 of STACK with return value` | z |
| 1020 | `replace item sp of STACK with item sp+3 of STACK` | x |
| 1019 | `replace item sp-1 of STACK with item sp of STACK` | x |
| 1018 | `replace item sp-2 of STACK with (item sp-1 of STACK - 48) * 100` | 100(x - 48) |
| 1017 | `replace item sp-3 of STACK with item sp+2 of STACK` | y |
| 1016 | `replace item sp-4 of STACK with item sp-3 of STACK` | y |
| 1015 | `replace item sp-5 of STACK with (item sp-4 of STACK - 48) * 10` | 10(y - 48) |
| 1014 | `replace item sp-6 of STACK with item sp+1 of STACK` | z |
| 1013 | `replace item sp-7 of STACK with item sp-6 of STACK` | z |
| 1012 | `replace item sp-8 of STACK with (item sp-2 of STACK - 48)` | 100(x - 48) - 48 |
| 1011 | `replace item sp-9 of STACK with (item sp-8 of STACK + item sp-5 of STACK)` | 100(x - 48) + 10(y - 48) - 48 |
| 1010 | `replace item sp-10 of STACK with (item sp-9 of STACK + item sp-7 of STACK)` | 100(x - 48) + 10(y - 48) + z - 48 |

Now we get a hint from one of the organizers:

> '0' equals forty eight

This means that item 1010 `100(x - 48) + 10(y - 48) + z - 48` is just the 3 digit number we input (or other unicode characters if we need a value greater than 999)

Now back to item 1024. Depending on its value, different `if` blocks are run, which all increase `winning` by 1, but those `if` blocks also need item 1009 of the stack to be 0.

Additionally, item 1009 has different values depending on which segment of the code is being run.

| item 1024 | item 1009 |
| --- | --- |
| 4 | item 1010 - 119 |
| 3 | item 1010 - 80 |
| 2 | item 1010 - 67 |
| 1 | item 1010 - 119 |

item 1024 starts at 4, so the first 3 characters are 119, the next 3 are 080, then 067, and 119
The passcode is `119080067119`

![TTY is wPCw](/static/BlahajCTF2023/nyan_6.PNG)

{% ccb caption:Untitled url:'https://pastebin.com/3iE7wPCw' url_text:'Source' wrapped:true %}
 
WOW! good job making it this far, seriously. ~ scuffed 
 
blahaj{1ch1_n1_54n_ny4!_4r16470}
{% endccb %}

`blahaj{1ch1_n1_54n_ny4!_4r16470}`

[Leat\'eq - Tokyo](https://youtu.be/XlrWmtUdoOk)