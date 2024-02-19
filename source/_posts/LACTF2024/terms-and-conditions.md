---
title: terms-and-conditions
date: 2024-02-19 08:00
tags: 
- web
- author-hartmannsyg
categories: LACTF 2024
---

We have an "I Accept" button that we need to click, but it keeps running away from our cursor

![](./static/LACTF2024/terms-and-conditions-0.png)

If we open up console, it says "NO CONSOLE ALLOWED"

![](./static/LACTF2024/terms-and-conditions-1.png)

However, this check is only checking for window resize:

{% ccb lang:js caption:index.html gutter1:156-162 %}
            setInterval(function() {
                if (window.innerHeight !== height || window.innerWidth !== width) {
                    document.body.innerHTML = "<div><h1>NO CONSOLE ALLOWED</h1></div>";
                    height = window.innerHeight;
                    width = window.innerWidth;
                }
            }, 10);
{% endccb %}

It only checks for changes in window size, so if we reload it while console is open we can bypass this check:

![](./static/LACTF2024/terms-and-conditions-2.png)

Now if we click the button using javascript (by typing this in the console):

{% ccb lang:js caption:index.html gutter1:156-162 %}
document.getElementById('accept').click()
{% endccb %}

We get an alert popup that says `lactf{that_button_was_definitely_not_one_of_the_terms}`    