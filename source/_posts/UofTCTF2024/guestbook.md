---
title: Guestbook
date: 2024-01-16
tags: 
- web
- author-hartmannsyg
categories: UofTCTF 2024
---

written by {% person hartmannsyg %}

(this was solved only once I realized it was a google sheets file *after* the CTF ended :/)

we are given a html file:

{% ccb lang:html scrollable:true caption:guestbook.html %}
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>My Guestbook</title>
    <script async=false defer=false>
        fetch("https://script.google.com/macros/s/AKfycbyX5Y5MkBLDO4JrB67pTTx7A6JI_ajT-3aBXC1UvnurQjbLYmDJjUfPTne-cyGsKxY8/exec?sheetId=1PGFh37vMWFrdOnIoItnxiGAkIqSxlJDiDyklp9OVtoQ").then(x=>x.json()).then(x=>{
            x.slice(x.length-11).forEach(entry =>{
                const el = document.createElement("li");
                el.innerText = entry.Name + " - " + entry.Message
                document.getElementById("entries").appendChild(el)
            })
            document.getElementById("loading")?.remove();
        })
    </script>
</head>
<body>
<h1>
    Hi! I made this guestbook for my site, please sign it.
</h1>
<iframe name="dummyframe" id="dummyframe" style="display: none;"></iframe>
<h3 style="margin: 0">Last 10 user entries in the guestbook:</h3>
<p id="loading" style="margin: 0">Loading...</p>
<ul id="entries" style="margin: 0">
</ul>

<h3>Sign the guestbook:</h3>
<form method="POST" action="https://script.google.com/macros/s/AKfycbyX5Y5MkBLDO4JrB67pTTx7A6JI_ajT-3aBXC1UvnurQjbLYmDJjUfPTne-cyGsKxY8/exec?sheetId=1PGFh37vMWFrdOnIoItnxiGAkIqSxlJDiDyklp9OVtoQ">
  <input id="name" name="name" type="text" placeholder="Name" required>
  <input id="message" name="message" type="text" placeholder="Message" required>
  <button type="submit">Send</button>
</form>
</body>
</html>
{% endccb %}

at the end of the url we see `/exec?sheetId=1PGFh37vMWFrdOnIoItnxiGAkIqSxlJDiDyklp9OVtoQ` which pretty much confirms that we are accessing a google sheet with a sheet id of `1PGFh37vMWFrdOnIoItnxiGAkIqSxlJDiDyklp9OVtoQ`.

So I went to https://docs.google.com/spreadsheets/d/1PGFh37vMWFrdOnIoItnxiGAkIqSxlJDiDyklp9OVtoQ :

![](/static/UofTCTF2024/guestbook.png)

There doesnt seem to be any flags, but it might be hidden in the sheet. So using the google sheets API from https://scripts.google.com

```js
function myFunction() {
  const id = "1PGFh37vMWFrdOnIoItnxiGAkIqSxlJDiDyklp9OVtoQ";
  const sheet = SpreadsheetApp.openById(id);
  const sheets = sheet.getSheets();
  const sheet0 = sheets[0];
  // console.log(sheet0.getName())
  // const sheet1 = sheets[1];
  // console.log(sheet1.getName())
  // const sheet2 = sheets[2];
  // console.log(sheet2.getName())

  const data0 = sheet0.getDataRange().getValues();
  console.log(data0)
}
```

{% ccb terminal:true lang:js %}
[ [ 'Name', 'Message', 'Hidden' ],
  [ 'uoftctf{@PP 5cRIP7', ' !5 s0 coOL}', true ],
{% endccb %}

the flag is `uoftctf{@PP 5cRIP7 !5 s0 coOL}`

There are other ways to solve this (from @bliutech on discord): https://github.com/uclaacm/lactf-archive/blob/main/2023/misc/hidden-in-plain-sheets/solutions.md