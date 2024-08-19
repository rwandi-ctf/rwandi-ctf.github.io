---
title: Revsite2
date: 2024-08-19
tags: 
- rev
- wasm
- author-fs
categories: LITCTF 2024
---

written by {% person fs %} (solved by {% person fs %} and {% person tomato %})

> watch ads for a free flag, with amazing data integrity (patent not pending) URL: http://litctf.org:31785/

We are given website that has a 'visit_ad' button and each time we click it, there's a counter that goes up by 1 (and also redirected to a rickroll wow). To get the flag, we need to spam the counter till the counter's value matches 10^18. 

Firstly, I inspected at the html elements and found a div element with the id flag hidden. it lists a bunch of a chracters from a-z,0-9 defined as such 

```
style="position: absolute; text-align: center; left: 1000px;"
```

and when we remove the hidden tag from the element, we see 'LITCTF{' being displayed. 

Obviously, 10^18 is a ridiculous number and it'd probably take you days/weeks or even months to get to that number. So, to spare us that pain, the author also attaches some wasm and js code to the website which has probably like 10000 lines. 

Upon looking at the source code, we find that there is a visit_ad() function but to understand what the function does, we need to look through 1000 lines of wasm code. That is not really feasible (although I tried doing that at 1 am and probably went braindead after that).

I researched around and found out there's a tool called wasm2c plugin for ghidra that can convert the wasm code to actually readable c code. I installed it and disassembling the code allowed me to get the following relevant data...

```c

void export::visit_ad(void)

{
  //bunch of decalrations...
  
  local_8 = lRam00010320 + 0x75bcd15;
  if (lRam00010300 == local_8) {
    lRam00010300 = lRam00010300 + 1;
    lRam00010308 = lRam00010308 + lRam00010320 * 3 * lRam00010320 + lRam00010320 * 5 + 3;
    lRam00010310 = lRam00010310 +
                   lRam00010320 * 8 * lRam00010320 * lRam00010320 + lRam00010320 * 3 * lRam00010320
                   + lRam00010320 * 3 + 8;
    lRam00010320 = lRam00010320 + 1;
    local_710[0] = lRam00010320;
    unnamed_function_5(local_70,s_document.getElementById('pts').i_ram_000100aa,local_710);
    import::env::emscripten_run_script(local_70);
    local_78 = lRam00010320 * lRam00010320 * lRam00010320 + lRam00010320 * lRam00010320 +
               lRam00010320 + 1;
    if (lRam00010308 == local_78) {
      if (lRam00010320 == 1000000000000000000) {
        import::env::emscripten_run_script(s_document.getElementById('flag')._ram_0001002d);
        local_800[0] = (int)(char)((byte)(lRam00010310 >> 1) ^ 0x75);
        local_7f8 = lRam00010310 >> 0x29 & 0x1ffU ^ 0x110;
        unnamed_function_5(local_e0,s_document.getElementById('%c').st_ram_000100e6,local_800);
        import::env::emscripten_run_script(local_e0);
        local_7f0[0] = (int)(char)((byte)(int)(lRam00010310 >> 0x2e) ^ 199);
        local_7e8 = lRam00010310 >> 0x2b & 0x1ffU ^ 0x144;
        unnamed_function_5(local_150,s_document.getElementById('%c').st_ram_000100e6,local_7f0);
        import::env::emscripten_run_script(local_150);
        local_7e0[0] = (int)(char)((byte)(lRam00010310 >> 9) ^ 0x69);
        local_7d8 = lRam00010310 >> 0x24 & 0x1ffU ^ 0x131;
        unnamed_function_5(local_1c0,s_document.getElementById('%c').st_ram_000100e6,local_7e0);
        import::env::emscripten_run_script(local_1c0);
        local_7d0[0] = (int)(char)((byte)(int)(lRam00010310 >> 0x2f) ^ 0xa7);
        local_7c8 = lRam00010310 >> 0x1c & 0x1ffU ^ 0x1e;
        unnamed_function_5(local_230,s_document.getElementById('%c').st_ram_000100e6,local_7d0);
        import::env::emscripten_run_script(local_230);
        local_7c0[0] = (int)(char)((byte)(lRam00010310 >> 0x12) ^ 0x82);
        local_7b8 = lRam00010310 >> 5 & 0x1ffU ^ 0xd2;
        unnamed_function_5(local_2a0,s_document.getElementById('%c').st_ram_000100e6,local_7c0);
        import::env::emscripten_run_script(local_2a0);
        local_7b0[0] = (int)(char)((byte)(lRam00010310 >> 0x17) ^ 6);
        local_7a8 = lRam00010310 >> 0x17 & 0x1ffU ^ 0xb;
        unnamed_function_5(local_310,s_document.getElementById('%c').st_ram_000100e6,local_7b0);
        import::env::emscripten_run_script(local_310);
        local_7a0[0] = (int)(char)((byte)(int)(lRam00010310 >> 0x2e) ^ 0xc5);
        local_798 = lRam00010310 >> 0x1c & 0x1ffU ^ 0x2d;
        unnamed_function_5(local_380,s_document.getElementById('%c').st_ram_000100e6,local_7a0);
        import::env::emscripten_run_script(local_380);
        local_790[0] = (int)(char)((byte)(int)(lRam00010310 >> 0x36) ^ 0x2d);
        local_788 = lRam00010310 >> 0x23 & 0x1ffU ^ 0x151;
        unnamed_function_5(local_3f0,s_document.getElementById('%c').st_ram_000100e6,local_790);
        import::env::emscripten_run_script(local_3f0);
        local_780[0] = (int)(char)((byte)(int)(lRam00010310 >> 0x33) ^ 0x6c);
        local_778 = lRam00010310 >> 1 & 0x1ffU ^ 0x68;
        unnamed_function_5(local_460,s_document.getElementById('%c').st_ram_000100e6,local_780);
        import::env::emscripten_run_script(local_460);
        local_770[0] = (int)(char)((byte)(int)(lRam00010310 >> 0x27) ^ 0xf);
        local_768 = lRam00010310 >> 0x34 & 0x1ffU ^ 0x1f0;
        unnamed_function_5(local_4d0,s_document.getElementById('%c').st_ram_000100e6,local_770);
        import::env::emscripten_run_script(local_4d0);
        local_760[0] = (int)(char)((byte)(lRam00010310 >> 0x1e) ^ 0x16);
        local_758 = lRam00010310 >> 0x2b & 0x1ffU ^ 0x1ff;
        unnamed_function_5(local_540,s_document.getElementById('%c').st_ram_000100e6,local_760);
        import::env::emscripten_run_script(local_540);
        local_750[0] = (int)(char)((byte)(int)(lRam00010310 >> 0x2e) ^ 0xc4);
        local_748 = lRam00010310 >> 0x29 & 0x1ffU ^ 0xbb;
        unnamed_function_5(local_5b0,s_document.getElementById('%c').st_ram_000100e6,local_750);
        import::env::emscripten_run_script(local_5b0);
        local_740[0] = (int)(char)((byte)(lRam00010310 >> 0x17) ^ 0x42);
        local_738 = lRam00010310 >> 0x13 & 0x1ffU ^ 0x16a;
        unnamed_function_5(local_620,s_document.getElementById('%c').st_ram_000100e6,local_740);
        import::env::emscripten_run_script(local_620);
        local_730[0] = (int)(char)((byte)(lRam00010310 >> 0xb) ^ 0xec);
        local_728 = lRam00010310 >> 0x34 & 0x1ffU ^ 0x199;
        unnamed_function_5(local_690,s_document.getElementById('%c').st_ram_000100e6,local_730);
        import::env::emscripten_run_script(local_690);
        local_720[0] = (int)(char)((byte)(int)(lRam00010310 >> 0x2e) ^ 0x8d);
        local_718 = lRam00010310 >> 0x18 & 0x1ffU ^ 0xa8;
        unnamed_function_5(local_700,s_document.getElementById('%c').st_ram_000100e6,local_720);
        import::env::emscripten_run_script(local_700);
      }
    }
    else {
      import::env::emscripten_run_script(s_document.body.innerHTML_=_'data_i_ram_0001005d);
    }
  }
  else {
    import::env::emscripten_run_script(s_document.body.innerHTML_=_'data_i_ram_0001005d);
  }
  return;
}

```

Initially, we did not really understand the lRamxxxxxxx variables since we never really did wasm challenges before but after looking through the stack/memory via google chrome's dev tools, we realise that those refer to memory addresses. The 2 most important variables are lRam00010310 and lRam00010320. If we look through the stack memory, we relalise that lRam00010320 refers to the counter variable we talked about earlier. You can also figure this out via the condition check in the C code 

```c
if (lRam00010320 == 1000000000000000000){
    ///do some stuff to get the flags.
}
```
By looking closely at the C code, we also figure out lRam00010310 is a derived variable from lRam00010320. 
```c    
lRam00010310 = lRam00010310 +
                   lRam00010320 * 8 * lRam00010320 * lRam00010320 + lRam00010320 * 3 * lRam00010320
                   + lRam00010320 * 3 + 8;
```
Now, if we let lRam00010320 be x, we can translate this expression into a recursive series where
```bash 
f(x+1)=f(x)+ 8x^3 +3x^2 + 3x + 8
```
To solve this recursive series, we need to first establish the base value of f(0). To do that we need to look at chrome dev tools. We need to put a breakpoint before emscripten_run_script (which is just some compiling thing and how it actually works is not that important to the challenge but we need to set a breakpoint before it since it allows us to view the stack values before it calls the function) and run the function visit_ad(). Viewing the memory address at 0x10310 tells at the base value is 0xb. We then need to find out the value of x. We can see that the check of whether lRam10320 is 10^18 is carried out after this line of code.

```c
lRam00010320 = lRam00010320 + 1;
```

This means x=lRam00010320 is 10^18-1. 

Using the formula of recurive series, we can defined lRam00010310 as the sum of f(0)+ sum of 8x^3 (x from 0 to 10^18-1) + sum of 3x^2 (x from 0 to 10^18-1) + sum of 3x (x from 0 to 10^18-1) + 8*(10^18-1). A bit of googling can tell you how to derive these sums (just maths).

```py
bur = 0xb (starting value of lRam00010310)
N =  1000000000000000000-1 (intended value f lRam00010320)
lRam00010310 = (8*((N^2)*((N+1)^2)))//4 + (3*N*(N+1)*(2*N+1))//6 + (3 * N*(N+1))//2 + 8*N
```

After which, we just sub in the values and using the formula for recursive series we get f(10^18)=1999999999999999997000000000000000002000000000000000006999999999999999992. 

We then look at the bulk of the code which contains a bunch of shihfts and xors of lRam0010310.

```c
local_7a0[0] = (int)(char)((byte)(int)(lRam00010310 >> 0x2e) ^ 0xc5);
local_798 = lRam00010310 >> 0x1c & 0x1ffU ^ 0x2d;
unnamed_function_5(local_380,s_document.getElementById('%c').st_ram_000100e6,local_7a0);
import::env::emscripten_run_script(local_380);
```

But what does unnamed_function_5() refer to? When setting a breakpoint at the first emscripten_run_script in chrome dev tools and running the visit_ad() funciton, we take a look through the stack values and. we notice one of the stack values ($var_0) points to 65536. Looking at that location and scrolling down a bit, we see that there is a piece of code that says

```
document.getElementById('pts').innerHTML='%lld'. document.getElementById('%c').style.left='%lld'px.
```

We now see that it's taking a specific character (%c) and shifts it to the left by a certain number of pixels (%lld). Looking through the code a bit more, it seems clear what these chracters are what what the position shift offsets are.

local7a0[0] refers to the character of the flag and local_798 refers to the number of pixels it is shifted by. We then code out a function that takes lRam00010320 performs the shifts and xors to obtain the characters of the flag and the pixels it is shifted by and sort it with respect to increasing values of the shift. We also see this is done for multiple other chracters as we scroll down the source code even further.

Hence, we can code out a programe that takes out calculated lRam0010310 value, perform the shifts and xors as mentiomned, calculating the value of the character and the position of which the chracters are shifted by. We can then store these characters in an array and shift these characters around based on the positions each chracter is shifted by in a decreasing order. (since the more left each chracter is shifted, the more likely it is the close to the start of the flag).

Hence, we code out the following programme as such.
```py
bur = 0xb #starting value of lRam00010310
import numpy as np

N =  1000000000000000000-1

lRam00010310 =(8*((N^2)*((N+1)^2))//4) + (3*N*(N+1)*(2*N+1)//6) + (3*N*(N+1)//2) + (8*N)

print(lRam00010310)

lRam00010310+=bur

result = []
shifts_and_xors = [
    (1, 0x75), (0x2e, 199), (9, 0x69), (0x2f, 0xa7), (0x12, 0x82), (0x17, 6),
    (0x2e, 0xc5), (0x36, 0x2d), (0x33, 0x6c), (0x27, 0xf), (0x1e, 0x16), 
    (0x2e, 0xc4), (0x17, 0x42), (0xb, 0xec), (0x2e, 0x8d)
]

for shift, xor in shifts_and_xors:
    result.append(((lRam00010310 >> shift & 0xff) ^ xor))#calculating the value of chracters of the flag
print(bytes(result))
chars = result 

bur = 0xb

N =  1000000000000000000-1

lRam00010310 =(8*((N^2)*((N+1)^2))//4) + (3*N*(N+1)*(2*N+1)//6) + (3*N*(N+1)//2) + (8*N)

lRam00010310+=bur
shift_xor_values = [
(0x29, 0x110), (0x2b, 0x144), (0x24, 0x131), (0x1c, 0x1e), (5, 0xd2),
(0x17, 0xb), (0x1c, 0x2d), (0x23, 0x151), (1, 0x68), (0x34, 0x1f0),
(0x2b, 0x1ff), (0x29, 0xbb), (0x13, 0x16a), (0x34, 0x199), (0x18, 0xa8)
]

result = [(lRam00010310 >> shift & 0x1ff) ^ xor for shift, xor in shift_xor_values]#calculaing the pixel shifts amount for each chracter
a=np.argsort(np.array(result))#sorting the array based on the shifts
print(a)
print("".join( chr(i) for i in chars))  
index=0

flag=[chars[i] for i in a]
print("".join([chr(i) for i in flag]))
```

Running this code, we then obtain part of the flag to be ```s0_l457minute!}``` and the full flag would be ```LITCTF{s0_l457minute!}```

In retrospect, this was really just an easy challenge as long as you figure out what lRam meant and figuring out this relationship between lRam00010320 and lRam00010310 f(x+1)=f(x)+ 8x^3 +3x^2 + 3x + 8. We wasted a lot of time looking through the wasm code instead of just converting into C. Overall, a fun challenge.
