---
title: flagchecker
date: 2023-12-05
tags:
- rev
categories: BlahajCTF 2023
---

solved by {% person hartmannsyg %}

> CTFd is overrated. My flag checker is both fast and secure!

We are given a binary that checks for a flag. Thankfully when we shove it to ghidra it is quite apparent what the flag is:

{% ccb gutter1:1-3,S,43-81,S,225-226 lang:c %}
undefined8 main(void)

{
//SKIP_LINE:(4-42)
  printf("Enter flag: ");
  __isoc99_scanf(&DAT_00102011,&local_38);
  if (local_38 == 'b') {
    if (local_37 == 'l') {
      if (local_36 == 'a') {
        if (local_35 == 'h') {
          if (local_34 == 'a') {
            if (local_33 == 'j') {
              if (local_32 == '{') {
                if (local_31 == 'w') {
                  if (local_30 == 'h') {
                    if (local_2f == '4') {
                      if (local_2e == '7') {
                        if (local_2d == '_') {
                          if (local_2c == 'D') {
                            if (local_2b == '3') {
                              if (local_2a == 'C') {
                                if (local_29 == '0') {
                                  if (local_28 == 'M') {
                                    if (local_27 == 'P') {
                                      if (local_26 == '1') {
                                        if (local_25 == 'L') {
                                          if (local_24 == '3') {
                                            if (local_23 == 'r') {
                                              if (local_22 == '_') {
                                                if (local_21 == 'd') {
                                                  if (local_20 == '0') {
                                                    if (local_1f == '_') {
                                                      if (local_1e == 'y') {
                                                        if (local_1d == '0') {
                                                          if (local_1c == 'U') {
                                                            if (local_1b == '_') {
                                                              if (local_1a == 'U') {
                                                                if (local_19 == 's') {
                                                                  if (local_18 == '3') {
                                                                    if (local_17 == '?') {
                                                                      if (local_16 == '}') {
                                                                        puts("Correct flag!");
                                                                      }
//SKIP_LINE:(82-224)
  return 0;
}
{% endccb %}

`blahaj{wh47_D3C0MP1L3r_d0_y0U_Us3?}`