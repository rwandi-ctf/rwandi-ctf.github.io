---
title: new-housing-portal
date: 2024-02-19 08:03
tags: 
- web
- xss
- author-hartmannsyg
categories: LACTF 2024
---

solved by {% person hartmannsyg %}

I'm too lazy to illustrate this, but the username and name field of accounts are vulnerable to xss. Raw html is reflected via the "view invitations" page.

So, if we can get the admin bot to visit our page, we can trigger an xss that lets the admin send a request to us.

Idea:
- create user1 with normal username (hartmannsyg02)
- create user2 whose username xss that sends request to user1
- user2 send invitation to samy
- adminbot: view invitation page
- samy gets xss-ed, sends a request to user1
- view deepdarksecret in user1

our xss payload into the username is:
{% ccb lang:html wrapped:true %}
<img src=x onerror='fetch("https://new-housing-portal.chall.lac.tf/finder",{headers:{"content-type":"application/x-www-form-urlencoded"},body:"username=hartmannsyg02", method:"POST"});' />
{% endccb %}

When that user ^ sends a request to the admin bot and the admin bot receives it, it sends an invite to us (in this case `hartmannsyg02`):

![](../../static/LACTF2024/new-housing-portal.png)