---
title: Hello World
---
Welcome to [Hexo](https://hexo.io/)! This is your very first post. Check [documentation](https://hexo.io/docs/) for more info. If you get any problems when using Hexo, you can find the answer in [troubleshooting](https://hexo.io/docs/troubleshooting.html) or you can ask me on [GitHub](https://github.com/hexojs/hexo/issues).

# Test

```py
from Crypto.Cipher import AES
a = "Normal codeblocks works ig"
print(a)
```

But I have copied [jktrn's](https://github.com/jktrn/enscribe.dev-hexo) codeblock thingy with all the bells and whistles

If you wanna add fancy things like captions, urls and scrolling etc

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

you can even do line breaks, hilight code as if it was added, deleted or just normally hilight it. Btw post-line break for some reason everything is -1 idk why you can try to comprehend the `ccb` source code at `themes/cactus/scripts/ccb.js`
{% ccb lang:js gutter1:1-3,S,6-7 caption:'hello world' url:https://example.com url_text:'hello world' diff_add:2 highlight:5 diff_del:6 %}
function helloworld(){
   console.log('balls');
}
//SKIP_LINE:(4-5)
helloWorld();
const rick = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
{% endccb %}

## Pasting (colored) stuff from terminal

the easiest way is to embed html into the md file like so:

{% ccb html:true terminal:true %}
<DIV STYLE="display:inline-block;white-space:pre;font-family:'Cascadia Code',monospace;font-size:13px;"><SPAN STYLE="color:#98C379;">┌──(</SPAN><SPAN STYLE="color:#61AFEF;">suwandi㉿ryan</SPAN><SPAN STYLE="color:#98C379;">)-[</SPAN><SPAN STYLE="color:#DCDFE4;">~/ctf/nbctf/pico</SPAN><SPAN STYLE="color:#98C379;">]<BR>└─</SPAN><SPAN STYLE="color:#61AFEF;">$</SPAN><SPAN STYLE="color:#DCDFE4;"> pwndbg vuln<BR>Reading symbols from </SPAN><SPAN STYLE="color:#98C379;">vuln</SPAN><SPAN STYLE="color:#DCDFE4;">...<BR>(No debugging symbols found in </SPAN><SPAN STYLE="color:#98C379;">vuln</SPAN><SPAN STYLE="color:#DCDFE4;">)<BR>Cannot convert between character sets `UTF-32' and `UTF-8'<BR></SPAN><SPAN STYLE="color:#E06C75;">pwndbg: loaded 147 pwndbg commands and 45 shell commands. Type </SPAN><SPAN STYLE="color:#C678DD;">pwndbg [--shell | --all] [filter] </SPAN><SPAN STYLE="color:#E06C75;">for a list.<BR>pwndbg: created </SPAN><SPAN STYLE="color:#C678DD;">$rebase</SPAN><SPAN STYLE="color:#E06C75;">, </SPAN><SPAN STYLE="color:#C678DD;">$ida </SPAN><SPAN STYLE="color:#E06C75;">GDB functions (can be used with print/break)<BR>------- tip of the day (disable with </SPAN><SPAN STYLE="color:#C678DD;">set show-tips off</SPAN><SPAN STYLE="color:#E06C75;">) -------<BR></SPAN><SPAN STYLE="color:#DCDFE4;">Use </SPAN><SPAN STYLE="color:#E5C07B;">plist </SPAN><SPAN STYLE="color:#DCDFE4;">command to dump elements of linked list<BR></SPAN><SPAN STYLE="color:#E06C75;">pwndbg&gt;</SPAN></DIV>
{% endccb %}

for this html, I used Windows Terminal (the new one), went into its Settings > Interaction > "Text formats to copy to the clipboard" > Change to "HTML"

I then removed all the `background-color:#0c0c0c;` attribute and also changed the `font-size` to `13px`

I still think it looks a bit weird but whatever

## Home page

honestly rn I think the home page is fine but if we ever wanna change it:

```bash
$ npm remove hexo-generator-index
```

Then we create a `source/index.md` file

## Quick Start (Everything below this was the original site code)

### Create a new post

``` bash
$ hexo new "My New Post"
```

More info: [Writing](https://hexo.io/docs/writing.html)

### Run server

``` bash
$ hexo server
```

More info: [Server](https://hexo.io/docs/server.html)

### Generate static files

``` bash
$ hexo generate
```

More info: [Generating](https://hexo.io/docs/generating.html)

### Deploy to remote sites

``` bash
$ hexo deploy
```

More info: [Deployment](https://hexo.io/docs/one-command-deployment.html)
