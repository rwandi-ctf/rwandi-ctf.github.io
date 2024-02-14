---
title: Heap
date: 2024-02-14
tags: 
- heap
- pwn
---

Slowly working through [https://github.com/shellphish/how2heap](shellphish/how2heap)

## fastbin_dup

> Tricking malloc into returning a nearly-arbitrary pointer by abusing the fastbin freelist.

[wargame sim](https://wargames.ret2.systems/level/how2heap_fastbin_dup_2.34)

{% ccb lang:bash terminal:true html:true %}
This file demonstrates a simple double-free attack with fastbins.
Fill up tcache first.
{% endccb %}

It then mallocs 8 chunks of size 8 and frees 7 of them:
```c
	void *ptrs[8];
	for (int i=0; i<8; i++) {
		ptrs[i] = malloc(8);
	}
	for (int i=0; i<7; i++) {
		free(ptrs[i]);
	}
```
This fills up tcache with 7 freed chunks, so freed chunks from now on are recorded down in **fastbins** (which is what we are exploiting)

(This is only needed if the glibc uses tcache, which it sometimes doesn't like the below section)

{% ccb lang:bash terminal:true html:true %}
<span class='string'>wdb</span>> heap chunks
<span class='variable strong'>address        prev_size      size inuse             fd             bk</span>
0x83e000                     0x290 <span class='deletion'>used</span> <span class='comment'>(initial chunk allocated from other things)</span>
0x83e290                      0x20 <span class='title'>free</span>           0x83e
0x83e2b0                      0x20 <span class='title'>free</span>        0x83ea9e
0x83e2d0                      0x20 <span class='title'>free</span>        0x83eafe
0x83e2f0                      0x20 <span class='title'>free</span>        0x83eade
0x83e310                      0x20 <span class='title'>free</span>        0x83eb3e
0x83e330                      0x20 <span class='title'>free</span>        0x83eb1e
0x83e350                      0x20 <span class='title'>free</span>        0x83eb7e
0x83e370                      0x20 <span class='deletion'>used</span>
<span class='string'>wdb</span>> heap tcache
<span class='variable'>(0x20)    tcache[0](7): </span>0x83e350 -> 0x83e330 -> 0x83e310 -> 0x83e2f0 -> 0x83e2d0
 -> 0x83e2b0 -> 0x83e290
{% endccb %}

We then allocate three buffers:

(in this calloc(1, n) is *basically* identical to malloc(n) I think?)
```c
	int *a = calloc(1, 8);
	int *b = calloc(1, 8);
	int *c = calloc(1, 8);
```

{% ccb terminal:true html:true %}
Allocating 3 buffers.
<span class='string'>wdb</span>> heap chunks
<span class='variable strong'>address        prev_size      size inuse             fd             bk</span>
0x83e000                     0x290 <span class='deletion'>used</span>                               
0x83e290                      0x20 <span class='title'>free</span>           0x83e               
0x83e2b0                      0x20 <span class='title'>free</span>        0x83ea9e               
0x83e2d0                      0x20 <span class='title'>free</span>        0x83eafe               
0x83e2f0                      0x20 <span class='title'>free</span>        0x83eade               
0x83e310                      0x20 <span class='title'>free</span>        0x83eb3e               
0x83e330                      0x20 <span class='title'>free</span>        0x83eb1e               
0x83e350                      0x20 <span class='title'>free</span>        0x83eb7e               
0x83e370                      0x20 <span class='deletion'>used</span>                               
0x83e390                      0x20 <span class='deletion'>used</span> <span class='comment'>(a)</span>
0x83e3b0                      0x20 <span class='deletion'>used</span> <span class='comment'>(b)</span>
0x83e3d0                      0x20 <span class='deletion'>used</span> <span class='comment'>(c)</span>
1st calloc(1, 8): 0x83e3a0
2nd calloc(1, 8): 0x83e3c0
3rd calloc(1, 8): 0x83e3e0
{% endccb %}

We then free a, then b, then double free a
```c
free(a);
free(b);
free(a);
```

Note: the addresses got moved cuz I restarted the binary
{% ccb terminal:true html:true %}
Freeing the first one...
<span class='string'>wdb</span>> heap chunks
<span class='variable strong'>address        prev_size      size inuse             fd             bk</span>
0x7a8000                     0x290 <span class='deletion'>used</span>                               
0x7a8290                      0x20 <span class='title'>free</span>           0x7a8               
0x7a82b0                      0x20 <span class='title'>free</span>        0x7a8508               
0x7a82d0                      0x20 <span class='title'>free</span>        0x7a8568               
0x7a82f0                      0x20 <span class='title'>free</span>        0x7a8548               
0x7a8310                      0x20 <span class='title'>free</span>        0x7a84a8               
0x7a8330                      0x20 <span class='title'>free</span>        0x7a8488               
0x7a8350                      0x20 <span class='title'>free</span>        0x7a84e8               
0x7a8370                      0x20 <span class='deletion'>used</span>                               
0x7a8390                      0x20 <span class='title'>free</span>           0x7a8  <span class='comment'>(a)</span>
0x7a83b0                      0x20 <span class='deletion'>used</span>                  <span class='comment'>(b)</span>
0x7a83d0                      0x20 <span class='deletion'>used</span>                  <span class='comment'>(c)</span>
<span class='string'>wdb</span>> heap fast
<span class='number'>(0x20)      fastbin[0]:</span> <span class="code-segment-highlight">0x7a8390</span> <span class='comment'>(a gets freed so it gets put on the fastbin free list)</span>
<span class='number'>(0x30)      fastbin[1]:</span> 0x0
<span class='number'>(0x40)      fastbin[2]:</span> 0x0
<span class='number'>(0x50)      fastbin[3]:</span> 0x0
<span class='number'>(0x60)      fastbin[4]:</span> 0x0
<span class='number'>(0x70)      fastbin[5]:</span> 0x0
<span class='number'>(0x80)      fastbin[6]:</span> 0x0
{% endccb %}
{% ccb terminal:true html:true %}
If we free a (0x7a83a0) again, things will crash because a (0x7a83a0) is at the top of
 the free list.
So, instead, we'll free b (0x7a83c0).
<span class='string'>wdb</span>> heap chunks
<span class='variable strong'>address        prev_size      size inuse             fd             bk</span>
  ⋮                             ⋮                      ⋮
0x7a8370                      0x20 <span class='deletion'>used</span>                               
0x7a8390                      0x20 <span class='title'>free</span>           0x7a8               
0x7a83b0                      0x20 <span class='title'>free</span>        0x7a8438               
0x7a83d0                      0x20 <span class='deletion'>used</span>                               
<span class='string'>wdb</span>> heap fast
<span class='number'>(0x20)      fastbin[0]:</span> 0x7a83b0 -> <span class='code-segment-highlight'>0x7a8390</span> <span class='comment'>(a -> b)</span>
  ⋮              ⋮
<span class='number'>(0x80)      fastbin[6]:</span> 0x0
Now, we can free a (0x7a83a0) again, since it's not the head of the free list.
<span class='string'>wdb</span>> heap fast
<span class='number'>(0x20)      fastbin[0]:</span> <span class='deletion strong'>0x7a8390</span> -> 0x7a83b0 -> <span class='deletion strong code-segment-highlight'>0x7a8390 (duplicate entry)</span> <span class='comment'>(a -> b -> a)</span>
{% endccb %}
{% ccb terminal:true html:true %}
Now the free list has [ 0x7a83a0, 0x7a83c0, 0x7a83a0 ]. If we malloc 3 times, we'll get 0x7a83a0 twice!
<span class='comment'>(malloc uses the last element on the free list [a, b, a], hence we get a (0x7a83a0) twice)</span>
<span class='number'>(0x20)      fastbin[0]:</span> <span class='deletion strong'>0x7a8390</span> -> 0x7a83b0 -> <span class='deletion strong code-segment-highlight'>0x7a8390 (duplicate entry)</span> <span class='comment'>(a -> b -> a)</span>
1st calloc(1, 8): 0x7a83a0 <span class='comment'>(there is an offset of 0x10 for the header metadata)</span>
<span class='number'>(0x20)      fastbin[0]:</span> 0x7a8390 -> <span class='code-segment-highlight'>0x7a83b0</span> -> <span class='deletion strong'>(invalid memory)</span>
2nd calloc(1, 8): 0x7a83c0
<span class='number'>(0x20)      fastbin[0]:</span> <span class='code-segment-highlight'>0x7a8390</span> -> <span class='deletion strong'>(invalid memory)</span>
3rd calloc(1, 8): 0x7a83a0
<span class='number'>(0x20)      fastbin[0]:</span> <span class='deletion strong'>(invalid memory)</span>
{% endccb %}

The danger here is that *2 different mallocs* will be *pointing to the same chunk*

This can be exploited if 1 chunk that gets malloc()ed has sensitive information, and the user can access it by doing some operation on the program that runs another malloc() and leak that input

## fastbin_dup_consolidate

```c
  void* p1 = malloc(0x40);
  void* p2 = malloc(0x40);
```

{% ccb terminal:true html:true %}
Allocated two fastbins: p1=0xc0f010 p2=0xc0f060
<span class='string'>wdb</span>> heap chunks
<span class='variable strong'>address        prev_size      size inuse             fd             bk</span>
0xc0f000                      0x50 <span class='deletion'>used</span>
0xc0f050                      0x50 <span class='deletion'>used</span>
{% endccb %}
```c
  free(p1);
```
the freed gets added to fastbin:
{% ccb terminal:true html:true %}
Now free p1!
<span class='string'>wdb</span>> heap chunks
<span class='variable strong'>address        prev_size      size inuse             fd             bk</span>
0xc0f000                      0x50 <span class='title'>free</span>             0x0
0xc0f050                      0x50 <span class='deletion'>used</span>
<span class='string'>wdb</span>> heap bins
Heap Info for Arena 0x7f72c5904b20
                   <span class='keyword'>top:</span> 0xc0f0a0 <span class='variable'>(size: 0x20f60)</span>
        <span class='keyword'>last_remainder:</span> 0x0
<span class='number'>(0x20)      fastbin[0]:</span> 0x0
<span class='number'>(0x30)      fastbin[1]:</span> 0x0
<span class='number'>(0x40)      fastbin[2]:</span> 0x0
<span class='number'>(0x50)      fastbin[3]:</span> <span class='code-segment-highlight'>0xc0f000</span>
<span class='number'>(0x60)      fastbin[4]:</span> 0x0
<span class='number'>(0x70)      fastbin[5]:</span> 0x0
<span class='number'>(0x80)      fastbin[6]:</span> 0x0
      <span class='keyword'>unsorted bins[0]:</span> 0x0
{% endccb %}
```c
  void* p3 = malloc(0x400);
```
{% ccb terminal:true html:true %}
Allocated large bin to trigger malloc_consolidate(): p3=0xc0f0b0
In malloc_consolidate(), p1 is moved to the unsorted bin.
<span class='string'>wdb</span>> heap chunks
<span class='variable strong'>address        prev_size      size inuse             fd             bk</span>
0xc0f000                      0x50 <span class='title'>free</span>  0x7f72c5904bb8 0x7f72c5904bb8
0xc0f050                      0x50 <span class='deletion'>used</span>
0xc0f0a0                     0x410 <span class='deletion'>used</span>
<span class='string'>wdb</span>> heap bins
Heap Info for Arena 0x7f72c5904b20
                   <span class='keyword'>top:</span> 0xc0f4b0 <span class='variable'>(size: 0x20b50)</span>
        <span class='keyword'>last_remainder:</span> 0x0
<span class='number'>(0x20)      fastbin[0]:</span> 0x0
<span class='number'>(0x30)      fastbin[1]:</span> 0x0
<span class='number'>(0x40)      fastbin[2]:</span> 0x0
<span class='number'>(0x50)      fastbin[3]:</span> 0x0
<span class='number'>(0x60)      fastbin[4]:</span> 0x0
<span class='number'>(0x70)      fastbin[5]:</span> 0x0
<span class='number'>(0x80)      fastbin[6]:</span> 0x0
      <span class='keyword'>unsorted bins[0]:</span> 0x0
<span class='variable'>(0x50)   small bins[4]:</span> <span class='code-segment-highlight'>0xc0f000</span>
{% endccb %}
```c
  free(p1);
```
the freed chunk once again gets added to fastbin:
{% ccb terminal:true html:true %}
Trigger the double free vulnerability!
We can pass the check in malloc() since p1 is not fast top.
<span class='string'>wdb</span>> heap bins
Heap Info for Arena 0x7f72c5904b20
                   <span class='keyword'>top:</span> 0xc0f4b0 <span class='variable'>(size: 0x20b50)</span>
        <span class='keyword'>last_remainder:</span> 0x0
<span class='number'>(0x20)      fastbin[0]:</span> 0x0
<span class='number'>(0x30)      fastbin[1]:</span> 0x0
<span class='number'>(0x40)      fastbin[2]:</span> 0x0
<span class='number'>(0x50)      fastbin[3]:</span> <span class='code-segment-highlight'>0xc0f000</span>
<span class='number'>(0x60)      fastbin[4]:</span> 0x0
<span class='number'>(0x70)      fastbin[5]:</span> 0x0
<span class='number'>(0x80)      fastbin[6]:</span> 0x0
      <span class='keyword'>unsorted bins[0]:</span> 0x0
<span class='variable'>(0x50)   small bins[4]:</span> 0xc0f000 <-> <span class='deletion strong'>0x0 (invalid memory)</span>
{% endccb %}

```c
malloc(0x40)
```
first malloc takes it from fastbin:
{% ccb terminal:true html:true %}
Trigger the double free vulnerability!
We can pass the check in malloc() since p1 is not fast top.
<span class='string'>wdb</span>> heap bins
Heap Info for Arena 0x7f72c5904b20
                   <span class='keyword'>top:</span> 0xc0f4b0 <span class='variable'>(size: 0x20b50)</span>
        <span class='keyword'>last_remainder:</span> 0x0
<span class='number'>(0x20)      fastbin[0]:</span> 0x0
<span class='number'>(0x30)      fastbin[1]:</span> 0x0
<span class='number'>(0x40)      fastbin[2]:</span> 0x0
<span class='number'>(0x50)      fastbin[3]:</span> <span class='code-segment-highlight'>0x0</span>
<span class='number'>(0x60)      fastbin[4]:</span> 0x0
<span class='number'>(0x70)      fastbin[5]:</span> 0x0
<span class='number'>(0x80)      fastbin[6]:</span> 0x0
      <span class='keyword'>unsorted bins[0]:</span> 0x0
<span class='variable'>(0x50)   small bins[4]:</span> 0xc0f000 <-> <span class='deletion strong'>0x0 (invalid memory)</span>
{% endccb %}

```c
malloc(0x40)
```
then the next malloc takes it from the duplicated one in small bin
{% ccb terminal:true html:true %}
Trigger the double free vulnerability!
We can pass the check in malloc() since p1 is not fast top.
<span class='string'>wdb</span>> heap bins
Heap Info for Arena 0x7f72c5904b20
                   <span class='keyword'>top:</span> 0xc0f4b0 <span class='variable'>(size: 0x20b50)</span>
        <span class='keyword'>last_remainder:</span> 0x0
<span class='number'>(0x20)      fastbin[0]:</span> 0x0
<span class='number'>(0x30)      fastbin[1]:</span> 0x0
<span class='number'>(0x40)      fastbin[2]:</span> 0x0
<span class='number'>(0x50)      fastbin[3]:</span> <span class='code-segment-highlight'>0x0</span>
<span class='number'>(0x60)      fastbin[4]:</span> 0x0
<span class='number'>(0x70)      fastbin[5]:</span> 0x0
<span class='number'>(0x80)      fastbin[6]:</span> 0x0
      <span class='keyword'>unsorted bins[0]:</span> 0x0
<span class='variable'>(0x50)   small bins[4]:</span> 0xc0f000 <-> <span class='deletion strong'>0x0 (invalid memory)</span>
{% endccb %}