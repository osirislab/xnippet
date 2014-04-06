# xnippet

## Original description by [Gonzalo J. Carracedo](https://twitter.com/BatchDrake)

I had an amazing weekend in the Xtrelan LAN Party here in Badajoz (Spain). Among other contests and activities, an entertaining hacking contest was brought by Miguel Gesteiro (@mgesteiro) again, and I decided to participate in it. And there I found a reversing challenge for Win32. I think it's not necessary to say I don't have any Windows machine, so I had to do the entire reversing via Wine + IDA.

After 32 fucking hours since the challenge was first presented, I finally found the solution, and because the precious time I spent starting the binary, waiting the condition for jumping to the breakpoint, blah, blah, blah I thought it would be a good idea to write a little tool to extract the exact function you want to test to a file, load and execute it separately. And that was what I was spending my time in this afternoon: xnippet.

xnippet is a tool that lets you load code snippets or isolated functions (no matter the operating system they came from), pass parameters to it in several formats (signed decimal, string, unsigned hexadecimal...), hook other functions called by the snippet and analyze the result. The tool is written in a way that will let me improve it in a future, defining new calling conventions and output argument pointers.

But still, I think the best way to illustrate its features is by a proof of concept against the challenge that costed me that much.

The challenge consisted of a binary embedded inside another binary which performed some mathematical calculus that is passed via SendMessage to another thread. The result must be strictly positive in order to crack it. Specifically, it calculates the result of a second grade equation with given coefficients a, b and c. The prototype of this mysterious function is something like this:

`
void checkPassword (int a, int b, int c, void *hWnd, void *parenthWnd);
`

The problem was I was not paying attention to how were the arguments being converted (the coefficients were read as chars from the password field and then converted to int, extending its sign). But let's forget that for a while and ask the following question to ourselves: is there a way to run that function to check how it behaves with different values for a, b, c *without* debugging the entire application?

The answer is yes, and the only tool we need is xnippet. The procedure is the following:

First, we have to locate the function we want to debug and save its bytes to a file. In my case was:

  402542:	55                   	push   %ebp
  402543:	8b ec                	mov    %esp,%ebp
  402545:	83 c4 fc             	add    $0xfffffffc,%esp
  402548:	9b db e3             	finit  
  40254b:	db 45 0c             	fildl  0xc(%ebp)
  40254e:	d8 c8                	fmul   %st(0),%st
  402550:	c7 45 fc fc ff ff ff 	movl   $0xfffffffc,-0x4(%ebp)
  402557:	db 45 fc             	fildl  -0x4(%ebp)
  40255a:	da 4d 08             	fimull 0x8(%ebp)
  40255d:	da 4d 10             	fimull 0x10(%ebp)
  402560:	de c1                	faddp  %st,%st(1)
  402562:	db 5d fc             	fistpl -0x4(%ebp)
  402565:	8b 45 fc             	mov    -0x4(%ebp),%eax
  402568:	83 f8 00             	cmp    $0x0,%eax
  40256b:	7c 46                	jl     0x4025b3
  40256d:	db 45 fc             	fildl  -0x4(%ebp)
  402570:	d9 fa                	fsqrt  
  402572:	db 45 0c             	fildl  0xc(%ebp)
  402575:	c7 45 fc ff ff ff ff 	movl   $0xffffffff,-0x4(%ebp)
  40257c:	da 4d fc             	fimull -0x4(%ebp)
  40257f:	de c1                	faddp  %st,%st(1)
  402581:	da 75 08             	fidivl 0x8(%ebp)
  402584:	c7 45 fc 02 00 00 00 	movl   $0x2,-0x4(%ebp)
  40258b:	da 75 fc             	fidivl -0x4(%ebp)
  40258e:	db 5d fc             	fistpl -0x4(%ebp)
  402591:	6a 00                	push   $0x0
  402593:	ff 75 fc             	pushl  -0x4(%ebp)
  402596:	68 0c 04 00 00       	push   $0x40c
  40259b:	ff 75 18             	pushl  0x18(%ebp)
  40259e:	e8 cb 00 00 00       	call   0x40266e
  4025a3:	6a 00                	push   $0x0
  4025a5:	6a 00                	push   $0x0
  4025a7:	6a 10                	push   $0x10
  4025a9:	ff 75 14             	pushl  0x14(%ebp)
  4025ac:	e8 c3 00 00 00       	call   0x402674
  4025b1:	eb 0e                	jmp    0x4025c1
  4025b3:	6a 00                	push   $0x0
  4025b5:	6a 00                	push   $0x0
  4025b7:	6a 10                	push   $0x10
  4025b9:	ff 75 14             	pushl  0x14(%ebp)
  4025bc:	e8 b3 00 00 00       	call   0x402674
  4025c1:	c9                   	leave  
  4025c2:	c2 14 00             	ret    $0x14

Note that the starting address (the base as I'll call it from now on) is 402542. We need to know this address because most of the jumps and calls we'll found are performed via relative addressing.

The next step is looking for every single call and jump outside the boundaries of the function. We need to do this carefully in order to keep the logic of our snippet: we must bind every single function this code depends on if we don't want it to crash (and debugging with xnippet, although possible, is primitive).

We see here three calls to two functions (0x402674 and 0x40266e, which after debugging with IDA happened to be SendMessage and PostMessage respectively, we don't really need this information, it should be enough knowing how many arguments are passed to each function we want to bind).

As I said above, this functions need to be, if not fully implemented, at least replaced with stubs. And since I run a Linux box, that will be our wise decision.

xnippet looks for functions expored by .so files, so I'm going to writte a couple of functions imitating PostMessage and SendMessage, I'll call it intercept.c:

```
#include <stdio.h>

int
PostMessage (void *hWnd, int msg, unsigned int wParam, unsigned int lParam)
{
  printf ("PostMessage (%p, %d, %d, %d)\n", hWnd, msg, wParam, lParam);
}

int
SendMessage (void *hWnd, int msg, unsigned int wParam, unsigned int lParam)
{
  printf ("SendMessage (%p, %d, %d, %d)\n", hWnd, msg, wParam, lParam);
}
```

Let's compile it:

`
% gcc intercept.c -o intercept.so --shared -fPIC
`

And now we have everything ready to start our execution. We bind the functions called by the snippet to the stubs we've just written and try it out:

`
% ./xnippet -b 0x402542 -f ./intercept.so:PostMessage:0x40266e -f ./intercept.so:SendMessage:0x402674 snippet.bin i:01 i:10: i:1 x:0xaaaaaaaa x:0xbbbbbbbb -m
`

xnippet accepts a few options, with -b I specify where the function must be loaded (our base address) and with -f I define a function binding. In this case, I bind 0x402674 to SendMessage inside intercept.so and 0x40266e to PostMessage. We can bind many functions to many different libraries (even the libc.so.6). -m  just draws a horizontal line to separate where the text output of the snipper starts and where it ends. The arguments after the filename are the arguments passed to the function, in format type:value. Type may be int (for integers), str (for strings, passing the pointer to the stack), u (unsigned decimal) and x (unsigned hexadecimal). With the above command, we're calling the snippet like this:

`
void snippet (1, 10, 1, (void *) 0xaaaaaaaa, (void *) 0xbbbbbbbb);
`

And the results are like this:

```
% ./xnippet -b 0x402542 -f ./intercept.so:PostMessage:0x40266e -f ./intercept.so:SendMessage:0x402674 snippet.bin i:01 i:10: i:1 x:0xaaaaaaaa x:0xbbbbbbbb -m
----------8<-----------------------------------
PostMessage (0xbbbbbbbb, 1036, 0, 0)
SendMessage (0xaaaaaaaa, 16, 0, 0)
----------8<-----------------------------------
```

Playing with the values we can discover different behaviors:

```
% ./xnippet -b 0x402542 -f ./intercept.so:PostMessage:0x40266e -f ./intercept.so:SendMessage:0x402674 snippet.bin i:01 i:10: i:20 x:0xaaaaaaaa x:0xbbbbbbbb -m
----------8<-----------------------------------
PostMessage (0xbbbbbbbb, 1036, -3, 0)
SendMessage (0xaaaaaaaa, 16, 0, 0)
----------8<-----------------------------------

% ./xnippet -b 0x402542 -f ./intercept.so:PostMessage:0x40266e -f ./intercept.so:SendMessage:0x402674 snippet.bin i:30 i:10: i:20 x:0xaaaaaaaa x:0xbbbbbbbb -m
----------8<-----------------------------------
SendMessage (0xaaaaaaaa, 16, 0, 0)
----------8<-----------------------------------
```

And the one I was looking for:

```
% ./xnippet -b 0x402542 -f ./intercept.so:PostMessage:0x40266e -f ./intercept.so:SendMessage:0x402674 snippet.bin i:01 i:-35: i:0 x:0xaaaaaaaa x:0xbbbbbbbb -m
----------8<-----------------------------------
PostMessage (0xbbbbbbbb, 1036, 35, 0)
SendMessage (0xaaaaaaaa, 16, 0, 0)
----------8<-----------------------------------
```

Which sends a 35, a positive value I can use with my crackme.

There are another interesting ways to use this. With -T xnippet triggers a trap the moment before performs the absolute jump against the snippet (which is performed via push / ret, stopping in the ret). With -e we can examinate the return value and with -r and -s we can analyze registers and siginfo structure after the execution.

Bugs:

It won't work outside 32 bits x86 Linux boxes.

I wanted to make it as portable as possible, but there's no much I can do with just a x86 machine. All the code is highly dependant on the underlying architecture, and well, I didn't compile it in other Unix flavor, but I have no hope on it.

By the moment, stdcall calling conventions are the only supported, but if you guys find this useful, I can implement pascal and winapi conventions with a few lines more.

I attached the xnippet in a single C file (which must be compiled with flag -ldl) and the files I used on this example. It should work without much trouble.

Hope you enjoy it :)
