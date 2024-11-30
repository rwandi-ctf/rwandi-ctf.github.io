---
title: Spot The Difference
date: 2024-11-30
tags: 
- forensics
- jpeg
- author-foo
categories: YBNCTF 2024
---

solved by {% person foo %}

> Can you fix this image for me?

We are given a JPEG image that is unopenable.

After uploading it to Aperi'Solve, it says that byte 0x55 is an unsupported marker.

After checking in a hex editor, this byte is in position 0x15. We replace its value with 0xdb, the correct value in that position for the application0 header.

We can then open the image, and read the barely visible flag in the middle (you have to squint really hard to see it at first).
