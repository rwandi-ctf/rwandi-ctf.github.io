---
title: pogn
date: 2024-02-19 08:04
tags: 
- web
- js
- author-hartmannsyg
categories: LACTF 2024
---

solved by {% person hartmannsyg %}

This is a pong game against a "perfect" AI.

I originally though of trying to get the ball velocity to be very high but the code more or less restricts that from happening. Instead, we had to make the ball *position* `NaN`

{% ccb lang:js gutter1:81-106 highlight:3,11 caption:server.js %}
      // check if there has been a winner
      // server wins
      if (ball[0] < 0) {
        ws.send(JSON.stringify([
          Msg.GAME_END,
          'oh no you have lost, have you considered getting better'
        ]));
        clearInterval(interval);

      // game still happening
      } else if (ball[0] < 100) {
        ws.send(JSON.stringify([
          Msg.GAME_UPDATE,
          [ball, me]
        ]));

      // user wins
      } else {
        ws.send(JSON.stringify([
          Msg.GAME_END,
          'omg u won, i guess you considered getting better ' +
          'here is a flag: ' + flag,
          [ball, me]
        ]));
        clearInterval(interval);
      }
{% endccb %}

We have to fail both the `ball[0] < 0 ` and `ball[0] < 100` check. But since we can't use an integer, we use `NaN`:

{% ccb lang:js %}
NaN < 0 == False
NaN < 100 == False
{% endccb %}

Another thing about NaN is that any mathematical operations on NaN gives NaN:

{% ccb lang:js %}
NaN + 1 = NaN
NaN - 1 = NaN
NaN * 2 = NaN
NaN / 2 = NaN
NaN ** 2 = NaN
{% endccb %}

We see how we can modify ball[0] such that it becomes NaN

{% ccb lang:js gutter1:71-73 caption:server.js %}
      // update ball position
      ball[0] += ballV[0] * dt;
      ball[1] += ballV[1] * dt;
{% endccb %}

we see that if we want `ball[0]` is NaN, `ballV[0]` has to be `NaN`. We see that ballV is modified on collisions:

{% ccb lang:js gutter1:61-64 caption:server.js %}
      // collision with user's paddle
      if (norm(sub(op, ball)) < collisionDist) {
        ballV = add(opV, mul(normalize(sub(ball, op)), 1 / norm(ballV)));
      }
{% endccb %}

we can control `opV` from our input `paddleV`:
{% ccb lang:js gutter1:117 caption:server.js %}
opV = mul(normalize(paddleV), 2);
{% endccb %}

{% ccb lang:js caption:server.js gutter1:41-42 %}
  const norm = ([x, y]) => Math.sqrt(x ** 2 + y ** 2);
  const normalize = (v) => mul(v, 1 / norm(v));
{% endccb %}

If we get `v = [0, 0]`, `norm(v) = 0`, and `1/norm(v)` will be `NaN`, causing `opV` to also be `NaN`, which cascades down all the way to `ball[0]` being `NaN` and getting us the flag.

{% ccb lang:js caption:solve.js gutter1:1-29 %}
const { WebSocket } = require('ws');

const ws = new WebSocket('ws://pogn.chall.lac.tf/ws');

ws.on('error', console.error);
ws.on('open', function open() {});
let ballPos

ws.on('message', function message(data) {
  const o = JSON.parse(data.toString());
  const type = o[0]
  if (type == 2) {
      console.log(o)
      return console.log('game ended')
  }
  ballPos = o[1][0]
  // console.log(ballPos)
  serverPos = o[1][1]
});

let i = 0

setInterval(() => {
  if (!ballPos) return
  i++;
  let ourPos = [50, ballPos[1]]
  let v = [0, 0]
  ws.send(JSON.stringify([1, [ourPos, v]]));
}, 50);
{% endccb %}

{% ccb lang:js wrapped:true %}
[
  2,
  'omg u won, i guess you considered getting better here is a flag: lactf{7_supp0s3_y0u_g0t_b3773r_NaNaNaN}',
  [ [ null, null ], [ 95, 0 ] ]
]
{% endccb %}