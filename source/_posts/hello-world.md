---
title: Hello World
date: 2023-12-02 00:00:00
---
Welcome to [Hexo](https://hexo.io/)! This is your very first post. Check [documentation](https://hexo.io/docs/) for more info. If you get any problems when using Hexo, you can find the answer in [troubleshooting](https://hexo.io/docs/troubleshooting.html) or you can ask me on [GitHub](https://github.com/hexojs/hexo/issues).

# Header 1
(Header 1 doesn't show in contents so maybe don't use them)
## Header 2
### Header 3
#### Header 4

## Code Blocks

### Normal

```py
from Crypto.Cipher import AES
a = "Normal codeblocks works ig"
print(a)
```

### Custom Code Block

But I have copied [jktrn's](https://github.com/jktrn/enscribe.dev-hexo) codeblock thingy with all the bells and whistles if you wanna add fancy things like captions, urls and scrolling etc

{% ccb caption:vuln-0.c lang:c url:'enscribe.dev/static/picoctf-2022/buffer-overflow/vuln-0.c' gutter1:1-44 url_text:'download source' scrollable:true %}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define FLAGSIZE_MAX 64

char flag[FLAGSIZE_MAX];

void sigsegv_handler(int sig) {
  printf("%s\n", flag);
  fflush(stdout);
  exit(1);
}

void vuln(char *input){
  char buf2[16];
  strcpy(buf2, input);
}

int main(int argc, char **argv){
  
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }
  
  fgets(flag,FLAGSIZE_MAX,f);
  signal(SIGSEGV, sigsegv_handler); // Set up signal handler
  
  gid_t gid = getegid();
  setresgid(gid, gid, gid);


  printf("Input: ");
  fflush(stdout);
  char buf1[100];
  gets(buf1); 
  vuln(buf1);
  printf("The program will exit now\n");
  return 0;
}
{% endccb %}

You can even do line breaks, highlight code as if it was added, deleted or just normally highlight it in yellow. Btw post-line break for some reason everything is -1 idk why you can try to comprehend the `ccb` source code at `themes/cactus/scripts/ccb.js`

{% ccb lang:js gutter1:1-3,S,6-7 caption:'Rickroll' url:https://www.youtube.com/watch?v=dQw4w9WgXcQ url_text:'rickroll' diff_add:2 highlight:5 diff_del:6 %}
function helloworld(){
   console.log('balls');
}
//SKIP_LINE:(4-5)
helloWorld();
const rick = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
{% endccb %}

{% ccb html:true %}
you can also <span class='code-segment-highlight'>highlight certain segments</span> of code by manually using html
{% endccb %}

{% ccb wrapped:true %}
For super long text, you can make it wrapped. So any exceeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeees gets wrapped
{% endccb %}

{% ccb terminal:true %}
If you want to simulate a terminal rather than a code editor, there's an option for that too
{% endccb %}



## Math?

We are using [this extension](https://adamliuuu.me/2021/01/15/Add-latex-support-for-hexo/)

### KaTeX

{% katex %}
c = \pm\sqrt{a^2 + b^2}
{% endkatex %}

### MathJax example

{% mathjax %}
c = \pm\sqrt{a^2 + b^2}
{% endmathjax %}

wait you can just use $$: 

$c = \pm\sqrt{a^2 + b^2}$

## People

inline people like {% person treeindustry %} {% person foo %} {% person tomato %} {% person hartmannsyg %} {% person fs %}

add people by editing `themes/cactus/scripts/person.js`

### Authoring

simply do `author-<name>` like so for tags, all tags that start with `author-` get hidden through some black magic at `themes/cactus/layout/_partial/post/tag.ejs`
```yaml
tags: 
- web
- author-hartmannsyg
```

## Pasting (colored) stuff from terminal

the easiest way is to embed html into the md file like so:

{% ccb html:true terminal:true %}
<DIV STYLE="display:inline-block;white-space:pre;font-family:'Cascadia Code',monospace;font-size:13px;"><SPAN STYLE="color:#98C379;">┌──(</SPAN><SPAN STYLE="color:#61AFEF;">rwandi㉿ryan</SPAN><SPAN STYLE="color:#98C379;">)-[</SPAN><SPAN STYLE="color:#DCDFE4;">~/ctf/nbctf/pico</SPAN><SPAN STYLE="color:#98C379;">]<BR>└─</SPAN><SPAN STYLE="color:#61AFEF;">$</SPAN><SPAN STYLE="color:#DCDFE4;"> pwndbg vuln<BR>Reading symbols from </SPAN><SPAN STYLE="color:#98C379;">vuln</SPAN><SPAN STYLE="color:#DCDFE4;">...<BR>(No debugging symbols found in </SPAN><SPAN STYLE="color:#98C379;">vuln</SPAN><SPAN STYLE="color:#DCDFE4;">)<BR>Cannot convert between character sets `UTF-32' and `UTF-8'<BR></SPAN><SPAN STYLE="color:#E06C75;">pwndbg: loaded 147 pwndbg commands and 45 shell commands. Type </SPAN><SPAN STYLE="color:#C678DD;">pwndbg [--shell | --all] [filter] </SPAN><SPAN STYLE="color:#E06C75;">for a list.<BR>pwndbg: created </SPAN><SPAN STYLE="color:#C678DD;">$rebase</SPAN><SPAN STYLE="color:#E06C75;">, </SPAN><SPAN STYLE="color:#C678DD;">$ida </SPAN><SPAN STYLE="color:#E06C75;">GDB functions (can be used with print/break)<BR>------- tip of the day (disable with </SPAN><SPAN STYLE="color:#C678DD;">set show-tips off</SPAN><SPAN STYLE="color:#E06C75;">) -------<BR></SPAN><SPAN STYLE="color:#DCDFE4;">Use </SPAN><SPAN STYLE="color:#E5C07B;">plist </SPAN><SPAN STYLE="color:#DCDFE4;">command to dump elements of linked list<BR></SPAN><SPAN STYLE="color:#E06C75;">pwndbg&gt;</SPAN></DIV>
{% endccb %}

for this html, I used Windows Terminal (the new one), went into its Settings > Interaction > "Text formats to copy to the clipboard" > Change to "HTML"

Then when you copy the thing, you have to somehow get the html instead of the raw text. Idk how to do that with python so I go to new tab, in the Inspect Element Console tab I paste in this js:
```js
document.addEventListener('paste', function(e) {
  var html = e.clipboardData.getData('text/html');
  html = html.replaceAll(/<.?html>/gi,'')
  html = html.replaceAll(/<.?head>/gi,'')
  html = html.replaceAll(/<.?body>/gi,'')
  html = html.replaceAll('<BR>','\n')
  html = html.replaceAll('<!--StartFragment -->','')
  html = html.replaceAll('<!--EndFragment -->','')
  html = html.replaceAll(/<div style=".+?;">/gi,'')
  html = html.replaceAll('</DIV>','')
  html = html.replaceAll(/background-color:#.+?;/gi,'')
  console.log(html)
})
```

then it logs the html for me

I then remove the `<HTML>`, `<HEAD>` and `<BODY>` tags all the `background-color:#0c0c0c;` attribute and also changed the `font-size` to `13px`