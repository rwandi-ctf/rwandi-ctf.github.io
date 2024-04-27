---
title: CSS Password
date: 2024-01-15
tags: 
- rev
- css
- author-hartmannsyg
categories: UofTCTF 2024
---

solved by {% person hartmannsyg %}

![The password is correct when all 5 LEDs turn on](/static/UofTCTF2024/css_password.png)

We basically have 19 "bytes", of which you can toggle each individual bit. Certain conditions have to be met for all 5 LED lights to light up.

If we look at the html code for the first LED:

```html
<div class="checker">
    <div class="checker__state"></div>
    <div class="checker__state"></div>
    <div class="checker__state"></div>
    <div class="checker__state"></div>
    <div class="checker__state"></div>
    <div class="checker__state"></div>
    <div class="checker__state"></div>
    <div class="checker__state"></div>
    <div class="checker__state"></div>
    <div class="checker__state"></div>
</div>
```

we have a bunch of `<div class="checker__state"></div>` (which are red circles) blocking the green background of the `<div class="checker">`.

If we look at the styling of the page, we see:

```css
/* LED1 */
/* b1_7_l1_c1 */
.wrapper:has(.byte:nth-child(1) .latch:nth-child(7) .latch__reset:active) .checker:nth-of-type(2) .checker__state:nth-child(1) {
    transform: translateX(0%);
    transition: transform 0s;
}

.wrapper:has(.byte:nth-child(1) .latch:nth-child(7) .latch__set:active) .checker:nth-of-type(2) .checker__state:nth-child(1) {
    transform: translateX(-100%);
    transition: transform 0s;
}

/* b1_8_l1_c2 */
.wrapper:has(.byte:nth-child(1) .latch:nth-child(8) .latch__reset:active) .checker:nth-of-type(2) .checker__state:nth-child(2) {
    transform: translateX(0%);
    transition: transform 0s;
}

.wrapper:has(.byte:nth-child(1) .latch:nth-child(8) .latch__set:active) .checker:nth-of-type(2) .checker__state:nth-child(2) {
    transform: translateX(-100%);
    transition: transform 0s;
}

⋮
and more
```

we need the `transform: translateX(-100%);` to move the `checker__state` div out of the way, for the LED to "turn green".
So we to fulfill the `.wrapper:has(.byte:nth-child(1) .latch:nth-child(7) .latch__set:active)` condition.

This means that in the 1st byte (`.byte:nth-child(1)`), on the 7th bit/latch (`.latch:nth-child(7)`), the latch must be *set* (`.latch__set:active`), i.e. have a value of `1`. If the latch must be *reset*, that means the bit must be set to `0`.

Working through the logic, we are able to find the flag:

{% ccb scrollable lang:python caption:solve.py %}
css = """
I pasted the css here, indentation and all, only removing the /* LED x */ comments
"""
chars = [
    [0, 0, 0, 0, 0, 0, 0, 0], #1
    [0, 0, 0, 0, 0, 0, 0, 0], #2
    [0, 0, 0, 0, 0, 0, 0, 0], #3
    [0, 0, 0, 0, 0, 0, 0, 0], #4
    [0, 0, 0, 0, 0, 0, 0, 0], #5
    [0, 0, 0, 0, 0, 0, 0, 0], #6
    [0, 0, 0, 0, 0, 0, 0, 0], #7
    [0, 0, 0, 0, 0, 0, 0, 0], #8
    [0, 0, 0, 0, 0, 0, 0, 0], #9
    [0, 0, 0, 0, 0, 0, 0, 0], #10
    [0, 0, 0, 0, 0, 0, 0, 0], #11
    [0, 0, 0, 0, 0, 0, 0, 0], #12
    [0, 0, 0, 0, 0, 0, 0, 0], #13
    [0, 0, 0, 0, 0, 0, 0, 0], #14
    [0, 0, 0, 0, 0, 0, 0, 0], #15
    [0, 0, 0, 0, 0, 0, 0, 0], #16
    [0, 0, 0, 0, 0, 0, 0, 0], #17
    [0, 0, 0, 0, 0, 0, 0, 0], #18
    [0, 0, 0, 0, 0, 0, 0, 0], #19
]

logics = css.split('\n        /* ')
for logic in logics:
    lines = logic.split('\n')
    line = lines[0][1:]
    comment_tokens = line.split('_')
    byte = int(comment_tokens[0])
    pos = int(comment_tokens[1])
    if "100" in lines[2]:
        chars[byte-1][pos-1] = 0
    else:
        chars[byte-1][pos-1] = 1

flag = ''

for char in chars:
    exp = 7
    num = 0
    for bit in char:
        num += bit * 2**exp
        exp -= 1
    flag += chr(num)

print(flag) # CsS_l0g1c_is_fun_3h
{% endccb %}