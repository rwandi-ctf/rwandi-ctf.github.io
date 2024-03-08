---
title: any% ssg
date: 2024-02-29
tags: 
- crypto
- LLL
- author-tomato
categories: LACTF 2024
---

> Check out this new open-source version of Minecraft my friend is making! They started working on it yesterday, but I want to speedrun it before anyone else can ... can you find me a seed that makes the end portal complete? Run the game with java -jar my-new-game.jar.
> Send your seed to nc chall.lac.tf 31170 to get the flag.

So we are given a bootleg Minecraft seed generator in a .jar file. Opening it, we can see that after entering a seed, it will generate a "world", which contains an end portal.

![](./static/LACTF2024/minecraft.png)

The end portal is the squares around the big orange square, (there are 16). If the circle is black, its not filled, if its green, its filled. We need to fill all 16 squares to win. 

## Generation

Lets take a look at how they generate the world:

{% ccb 
caption:Game.java
lang:java
gutter1:19-33
highlight:8-14
%}

private void generateBoard(){
    for (int i = 0; i<sizeX; i++) {
        for (int j = 0; j<sizeY; j++) {
            board.setTile(i,j,new Tile("grass"));
        }
    }
    for (int i = 0; i<5; i++) {
        board.generateCircle(r,new Tile("stone"));
    }
    for (int i = 0; i<3; i++) {
        board.generateCircle(r,new Tile("water"));
    }
    board.generateStronghold(r);
    board.updatePlayer();
}

{% endccb %}

First, it generates 5 stone circles, then 3 water circles, then finally the stronghold. Now, we look at how these are internally implemented. `generateCircle`:

{% ccb 
caption:Board.java
lang:java
gutter1:113-124
html:true
%}
public void generateCircle(CustomRandom r, Tile t) {
    int radius = Math.floorMod((int) <span class='code-segment-highlight'>r.nextLong()</span>, 15);
    int circleX = Math.floorMod((int) <span class='code-segment-highlight'>r.nextLong()</span>, sizeX);
    int circleY = Math.floorMod((int) <span class='code-segment-highlight'>r.nextLong()</span>, sizeY);
    for (int i = circleX - radius; i<= circleX + radius; i++) {
        for (int j = circleY - radius; j<=circleY+radius; j++) {
            if (i >= 0 && i < sizeX && j >= 0 && j < sizeY && (Math.pow(i-circleX,2) + Math.pow(j-circleY,2))<=Math.pow(radius,2)) {
                setTile(i,j,t);
            }
        }
    }
}

{% endccb %}

It calls `nextLong()`, which is a customly implemented RNG, 3 times, for the x-, y- coordinates, and the radius (not important lol). Since we generate 8 circles, thats 24 calls so far to `nextLong()`. Now, `generateStronghold`:

{% ccb 
caption:Board.java
lang:java
gutter1:60-74,S,111
html:true
%}
public void generateStronghold(CustomRandom r) {
    boolean[] filledEyes = new boolean[16];
    int strongholdLocationX = Math.floorMod((int)<span class='code-segment-highlight'>r.nextLong()</span>, sizeX-5);
    int strongholdLocationY = Math.floorMod((int)<span class='code-segment-highlight'>r.nextLong()</span>, sizeY-5);
    boolean allFilled = true;
    for (int i = 0; i<16; i++) {
        long n = <span class='code-segment-highlight'>r.nextLong()</span>;
        if (n > (9 * (1L << 52)/10L)) {
            filledEyes[i] = true;
        }
        else {
            filledEyes[i] = false;
            allFilled = false;
        }
    }
//SKIP_LINE:(75-110)
}

{% endccb %}

After 2 calls to `nextLong()` for the coordinates, the next 16 calls to `nextLong()` determine whether each eye has to be filled. Each output has to be greater than `(9 * (1L << 52)/10L)` which is basically {%katex%}\frac{9}{10} 2^{52} {%endkatex%}.

## CustomRandom

So, how exactly does `nextLong()` work?

{% ccb 
caption:CustomRandom.java
lang:java
gutter1:1-21
%}
import java.time.Instant;
public class CustomRandom {
    private long seed;
    private final long i = 3473400794307473L;

    public CustomRandom() {
        this.seed = Instant.now().getEpochSecond() ^ i;
    }

    public void setSeed(long seed) {
        this.seed = seed ^ i;
    }

    public long nextLong() {
        long m = 1L << 52;
        long c = 4164880461924199L;
        long a = 2760624790958533L;
        seed = (a *seed+ c) & (m -1L);
        return seed;
    }
}
{% endccb %}

So, you input a seed, and every time it needs to generate a new output, it does `seed = (a *seed+ c) & (m -1L)` and returns `seed`, so some sort of funny recurrence relation. This looks suspiciously like an LCG.

Upon closer exception, `m-1L` is just `1<<52 - 1` which is {%katex%}\underbrace{111\cdots1}_\textrm{51 1's}{%endkatex%}, so taking `&` with that takes the last 51 bits of `(a*seed+c)`. If you think about it, taking the last 3 digits of a number in decimal is the same as taking {%katex%}\pmod{10^3}{%endkatex%}, so similarly, taking the last 51 bits is the same as taking {%katex%}\pmod{2^{52}}{%endkatex%}.

Now, we have `seed = (a*seed + c) % (2**52)` which is actually an LCG. This means, that what we need to do is find a seed such that after {%katex%}24+2=26{%endkatex%} calls, the next 16 LCG outputs are all within the range {%katex%}\frac{9}{10} 2^{52}<x<2^{52}{%endkatex%}.

## LLL

i'm too tired so i'll write this tomorrow