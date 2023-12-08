---
title: Site Scavenger
date: 2023-12-05
tags:
- web
categories: BlahajCTF 2023
---

solved by {% person hartmannsyg %}

> After making a website on my favourite stuffed toy, the Blahaj, I made a flag and hid it somewhere on the website. But now I cannot find it! Please help me get my flag again 😢

This is a Flag Hunt challenge, with the flag split into multiple parts.

## Part 1

If we go to the `/about` page, we view the website's source (Inspect Element or Ctrl+U). Part 1 of the flag is at the bottom of the file:

{% ccb gutter1:193-199 lang:html %}
</body>

<!-- Oops, this is where I left the first part of the flag. -->
<!-- blahaj{i_l0v3_b14 -->
<!-- If only I knew where to find the other parts of the flag... -->

</html>
{% endccb %}

So the first part is `blahaj{i_l0v3_b14`

## Part 2

Many websites have a `./robots.txt` to instruct web robots (typically search engine robots) how to crawl pages on their website. It is also almost always used in these sort of "Flag Hunt" challenges. In the `/robots.txt` we have:

```
Oops, this is where I left the second part of the flag.
haj_and_y0u_shou
If only I knew where to find the other parts of the flag...
```

So the second part is `haj_and_y0u_shou`

## Part 3

The last part was harder. I didn't know where the next part could be, but after dirbusting a lot of trial and error, I found `/sitemap.xml`:

```xml
<sitemapindex>
    <sitemap>
        <loc>/</loc>
    </sitemap>
    <sitemap>
        <loc>/about</loc>
    </sitemap>
    <sitemap>
        <loc>/sitemap.xml</loc>
    </sitemap>
    <sitemap>
        <loc>/sup3r-s3cr3t</loc>
    </sitemap>
    <sitemap>
        <loc>/robots.xml</loc>
    </sitemap>
</sitemapindex>
```

We see an extremely suspicious `/sup3r-s3cr3t` endpoint. However when we went there they greeted us with:

```html
<p>GET functionality still in development</p><br><!-- TODO: Make this page request automatically POST -->
```

So I did a `POST` request to `/sup3r-s3cr3t`, and I received:

```
What is your fav_plush?
```

Just how many layers do you want this third part to be????

Anyways after fiddling with url parameters, Headers, and json, I submited a `x-www-form-urlencoded` (default) with `fav_plush: blahaj`:

```py
import requests

url = 'http://188.166.197.31:30015/sup3r-s3cr3t'

x = requests.post(url, data = {'fav_plush':'blahaj'})
print(x.text)
```

and I got the flag:

```html
            Welcome back, here is the 3rd part of the flag.<br>
            <code>1d_70o_^_^}</code>
            <br>Did you remember to collect the other 2 on the way?
```

Putting it all together: `blahaj{i_l0v3_b14haj_and_y0u_shou1d_70o_^_^}`
