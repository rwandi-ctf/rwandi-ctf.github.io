---
title: Verilog Count
date: 2024-05-09
tags: 
- misc
- author-hartmannsyg
categories: greyCTF 2024
---

solved by {% person hartmannsyg %}

> I want to count from 0
> Author: Hackin7
> `nc challs.nusgreyhats.org 31114`

we are given `run.py`, which takes our input verilog code and runs it with iverilog:

{% ccb terminal:true %}
iverilog -o ./vt -s test -c file_list.txt
vvp ./vt > output.txt
{% endccb %}

<details>
<summary>
<code>run.py</code> source code
</summary>

```py
#!/usr/bin/python3

import base64
import sys
import subprocess
import tempfile
import os
import shutil

# Replace this with the actual flag
FLAG = "grey{TEST_FLAG}"
BAD_WORDS = ['if', 'else', '?', '+']

CURR_DIR = os.getcwd()
def copy_and_run(verilog_code, directory_path='test'):
    output = None
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp()

    try:
        # Copy the directory into the temporary directory
        shutil.copytree(os.path.join(CURR_DIR, directory_path), os.path.join(temp_dir, os.path.basename(directory_path)))
        # Change the current working directory to the temporary directory
        os.chdir(os.path.join(temp_dir, directory_path))
        with open("solve.v", mode='w+') as f:
            f.write(verilog_code)
        # Run the shell script
        os.system('iverilog -o ./vt -s test -c file_list.txt')
        os.system('(vvp ./vt > output.txt )')
        with open('output.txt', 'r') as file:
            output = file.read().strip()
    except Exception as e:
        print(e)
    finally:
        # Cleanup: Remove the temporary directory and its contents
        shutil.rmtree(temp_dir)
        os.chdir(CURR_DIR)
        return output


def run_verilog_code(verilog_code):
    return copy_and_run(verilog_code)


def check_output(output, expected_output_file):
    with open(expected_output_file, 'r') as file:
        expected_output = file.read().strip()
    return output.strip() == expected_output

def main():
    try:
        # Receive Verilog code until 'END'
        enc_input = input("base64 encoded input: ")

        try:
            received_data = base64.b64decode(enc_input).decode()
        except:
            print("failed to decode input as base64 string")
            sys.exit(0)

        for word in BAD_WORDS:
            if word in received_data:
                print("Bad Words Detected")
                sys.exit(0)

        print("Received Verilog code!")

        # Run Verilog code
        output = run_verilog_code(received_data)

        # Check if output matches expected
        expected_output_file = 'expected_output.txt'
        if check_output(output, expected_output_file):
            print(f"Congratulations! Flag: {FLAG}")
        else:
            print("Output does not match expected.")

    finally:
        sys.exit(0)


main()
```
</details>

Apparently, our output should follow `expected_output.txt`:

{% ccb caption:expected_output.txt gutter1:1-10,S,131073-131077 terminal:true %}
clk 0, result          0
clk 1, result          1
clk 0, result          1
clk 1, result          2
clk 0, result          2
clk 1, result          3
clk 0, result          3
clk 1, result          4
clk 0, result          4
clk 1, result          5
/*SKIP_LINE:(...)*/
clk 0, result      65536
clk 1, result      65537
clk 0, result      65537
clk 1, result      65538
clk 0, result      65538
{% endccb %}

## Wtf is iverilog

This seems a bit like an "esolang" (esoteric language) challenges that ctfs will randomly have so oh well

Let's first checking [Wikipedia](https://en.wikipedia.org/wiki/Icarus_Verilog) (The Free Encyclopedia)

> **Icarus Verilog** is an implementation of the [Verilog](https://en.wikipedia.org/wiki/Verilog) hardware description language compiler that generates [netlists](https://en.wikipedia.org/wiki/Netlists) in the desired format ([EDIF](https://en.wikipedia.org/wiki/EDIF)) and a simulator.

uhhh idk what those are but alright then. I think my favoruite part of this (very short) Wikipedia page is this sentence:

> <u>Not even the author quite remembers when the project was first started</u>, but CVS records go back to 1998.

yikes

## Installing

Somehow this was quite troublesome. When I downloaded the challenge, I completely forgot that there was a `docker-compose.yml` given. So I googled online and went to their [*Fandom Website*](https://iverilog.fandom.com/wiki/Installation_Guide) (a *fandom wiki* for *documentation* ...)

I tried installing it on my WSL kali linux but I failed spectacularly, so I tried it on *Windows* instead. After a bunch of fumbling around I got their hello world example running:

{% ccb caption:hello.v gutter1:1-7 lang:verilog %}
module hello;
  initial 
    begin
      $display("Hello, World");
      $finish ;
    end
endmodule
{% endccb %}

## The objective

After the daunting task of getting iverilog, let's get to the point of this challenge.

The python script saved our input to `solve.v`, and then compiles both `solve.v` and `testbench.v` with:

{% ccb terminal:true %}
iverilog -o ./vt -s test -c file_list.txt
{% endccb %}

> `file_list.txt` in this case is a file that contains the list of files to be compiled:
> ```
solve.v
testbench.v
```

Let's look at `testbench.v`:

{% ccb caption:testbench.v lang:verilog gutter1:1-16 %}
module test();
    // Inputs
    reg clk;
    // Outputs
    wire [31:0] result;

    counter c(clk, result);

    initial begin
        clk = 0;
        $monitor("clk %b, result %d", clk, result);
        repeat(131076) begin
            #1 clk = ~clk;
        end
    end
endmodule
{% endccb %}

We see that if we simply try to run it, we encounter an error:

{% ccb terminal:true %}
C:\iverilog\bin>iverilog testbench.v
testbench.v:7: error: Unknown module type: counter
2 error(s) during elaboration.
*** These modules were missing:
        counter referenced 1 times.
***
{% endccb %}

## Debugging

as we thought, we need to make a `counter` module. Thankfully, we see that in the [iverilog *fandom* documentation](https://iverilog.fandom.com/wiki/Getting_Started) there is an implementation of the `counter` module:

```verilog
module counter(out, clk, reset);

  parameter WIDTH = 8;

  output [WIDTH-1: 0] out;
  input 	       clk, reset;

  reg [WIDTH-1: 0]   out;
  wire 	       clk, reset;

  always @(posedge clk or posedge reset)
    if (reset)
      out <= 0;
    else
      out <= out + 1;

endmodule // counter
```

Running both `testbench.v` and `counter.v` gives us:

{% ccb terminal:true %}
C:\iverilog\bin>iverilog testbench.v counter.v
testbench.v:7: error: Wrong number of ports. Expecting 3, got 2.
1 error(s) during elaboration.
{% endccb %}

we see that counter should have `clk` as its first parameter (are they called parameters? idk the terminology here) and `result` (which corresponds to `out` in the example code) as the second parameter, with no `reset` parameter:

{% ccb caption:testbench.v lang:verilog gutter1:1-16 highlight:7 %}
module test();
    // Inputs
    reg clk;
    // Outputs
    wire [31:0] result;

    counter c(clk, result);

    initial begin
        clk = 0;
        $monitor("clk %b, result %d", clk, result);
        repeat(131076) begin
            #1 clk = ~clk;
        end
    end
endmodule
{% endccb %}

So let's rewrite our counter module:

{% ccb lang:verilog caption:counter.v %}
module counter(clk, out);

  parameter WIDTH = 8;

  output [WIDTH-1: 0] out;
  input 	       clk;

  reg [WIDTH-1: 0]   out;
  wire 	       clk;

  always @(posedge clk)
    out <= out + 1;

endmodule // counter
{% endccb %}

Let's see what we error we get:

{% ccb terminal:true %}
C:\iverilog\bin>iverilog testbench.v counter.v
testbench.v:7: warning: Port 2 (out) of counter expects 8 bits, got 32.
testbench.v:7:        : Padding 24 high bits of the expression.
{% endccb %}

Alright let's make `out` be 32 bits

```verilog
  parameter WIDTH = 32;
```

aaaand we get an infinite loop...

{% ccb terminal:true %}
clk 0, result          x
clk 1, result          x
/*SKIP_LINE:(...)*/
{% endccb %}

???? Why isn't out outputting the result????

I then asked chatGPT and they suggested more code I had to debug. I won't get into the nitty-gritty debugging process but here are some takeaways:

-

I eventually arrived at:

{% ccb lang:verilog caption:solve.v gutter1:1-8 %}
module counter(input clk, output reg [31:0] result);
  initial begin
    result <= 0;
  end
  always @(posedge clk) begin
    result <= result - -1;
  end
endmodule
{% endccb %}
