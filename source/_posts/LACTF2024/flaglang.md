---
title: flaglang
date: 2024-02-19
tags: 
- web
- author-hartmannsyg
categories: LACTF 2024
---

When we try to select Flagistan (which contains the flag we want as the message):

![](./static/LACTF2024/flaglang-0.png)

We get sent to https://flaglang.chall.lac.tf/switch?to=Flagistan which gives "error: not authenticated for Flagistan".

{% ccb lang:js caption:app.js gutter1:27-50 highlight:16 %}
app.get('/switch', (req, res) => {
  if (!req.query.to) {
    res.status(400).send('please give something to switch to');
    return;
  }
  if (!countries.has(req.query.to)) {
    res.status(400).send('please give a valid country');
    return;
  }
  const country = countryData[req.query.to];
  if (country.password) {
    if (req.cookies.password === country.password) {
      res.cookie('iso', country.iso, { signed: true });
    }
    else {
      res.status(400).send(`error: not authenticated for ${req.query.to}`);
      return;
    }
  }
  else {
    res.cookie('iso', country.iso, { signed: true });
  }
  res.status(302).redirect('/');
});
{% endccb %}

We do not know any way to get their password, so let's try another method:

{% ccb lang:js caption:app.js gutter1:52-68 highlight:13 %}
app.get('/view', (req, res) => {
  if (!req.query.country) {
    res.status(400).json({ err: 'please give a country' });
    return;
  }
  if (!countries.has(req.query.country)) {
    res.status(400).json({ err: 'please give a valid country' });
    return;
  }
  const country = countryData[req.query.country];
  const userISO = req.signedCookies.iso;
  if (country.deny.includes(userISO)) {
    res.status(400).json({ err: `${req.query.country} has an embargo on your country` });
    return;
  }
  res.status(200).json({ msg: country.msg, iso: country.iso });
});
{% endccb %}

When we try to use /view and go to https://flaglang.chall.lac.tf/view?country=Flagistan , we get:
```json
{"err":"Flagistan has an embargo on your country"}
```

This is because we have a preexisting country as our cookie, which is embargoed by Flagistan:
{% ccb wrapped:true lang:yaml %}
Flagistan:
  iso: FL
  msg: "<REDACTED>"
  password: "<REDACTED>"
  deny: 
    ["AF","AX","AL","DZ","AS","AD","AO","AI","AQ","AG","AR","AM","AW","AU","AT","AZ","BS","BH","BD","BB","BY","BE","BZ","BJ","BM","BT","BO","BA","BW","BV","BR","IO","BN","BG","BF","BI","KH","CM","CA","CV","KY","CF","TD","CL","CN","CX","CC","CO","KM","CG","CD","CK","CR","CI","HR","CU","CY","CZ","DK","DJ","DM","DO","EC","EG","SV","GQ","ER","EE","ET","FK","FO","FJ","FI","FR","GF","PF","TF","GA","GM","GE","DE","GH","GI","GR","GL","GD","GP","GU","GT","GG","GN","GW","GY","HT","HM","VA","HN","HK","HU","IS","IN","ID","IR","IQ","IE","IM","IL","IT","JM","JP","JE","JO","KZ","KE","KI","KR","KP","KW","KG","LA","LV","LB","LS","LR","LY","LI","LT","LU","MO","MK","MG","MW","MY","MV","ML","MT","MH","MQ","MR","MU","YT","MX","FM","MD","MC","MN","ME","MS","MA","MZ","MM","NA","NR","NP","NL","AN","NC","NZ","NI","NE","NG","NU","NF","MP","NO","OM","PK","PW","PS","PA","PG","PY","PE","PH","PN","PL","PT","PR","QA","RE","RO","RU","RW","BL","SH","KN","LC","MF","PM","VC","WS","SM","ST","SA","SN","RS","SC","SL","SG","SK","SI","SB","SO","ZA","GS","ES","LK","SD","SR","SJ","SZ","SE","CH","SY","TW","TJ","TZ","TH","TL","TG","TK","TO","TT","TN","TR","TM","TC","TV","UG","UA","AE","GB","US","UM","UY","UZ","VU","VE","VN","VG","VI","WF","EH","YE","ZM","ZW"]
{% endccb %}
So if we go to https://flaglang.chall.lac.tf/view?country=Flagistan in an incognito tab with no cookies:

```json
{"msg":"lactf{n0rw3g7an_y4m7_f4ns_7n_sh4mbl3s}","iso":"FL"}
```