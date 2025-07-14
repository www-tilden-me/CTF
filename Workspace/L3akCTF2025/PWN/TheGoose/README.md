# The Goose Writeup

## Basics

When we unzip [chall.zip](./challenge.lock) we see that it contains a `Dockerfile` and a `chall` program which is x86_64.

We start by dumping the disassembled [chall](./chall) into [chall.dump](chall.dump) with `objdump -d chall > chall.dump`.

Then looking through the assembly code that makes up [chall](./chall) we can piece it back together again. From the assembly, we see that [chall](./chall) has 4 main functions:
- main
- setuser
- guess
- highscore

We can reassemble this manually or put the executable into something like [dogbolt](dogbolt.org) that gives its best attempts at a reassembled version.

From fixing up the reassembled version of [chall](./chall) that we got from dogbolt a little bit, we can get something like ([chall.reversed.c](./chall.reversed.c)).

This reassembled c code shows us that there are a number of vulnerabilities, highlighted in the comments in [chall.reversed.c](./chall.reversed.c), and helps us get an idea of how we will pwn the machine.

## Strategy

#### VULNS:
* We have a printf vuln from the second time we are asked for our name
	* It just prints out our name again
* We can overwrite the return address from the read vulnerability

For the read overflow we can achieve given the following call setup:
```
lea    -0x170(%rbp),%rax
mov    $0x400,%edx
mov    %rax,%rsi
mov    $0x0,%edi
mov    $0x0,%eax
call   1060 <read@plt>
```
So we can write far past the return address and farther onto the stack for our system vuln -- we will just need our shellcode

However, in order to even activate this we need to get the guess right. Luckily it is called like this:

```
srand(time(NULL))
nhonks = rand() % 0x5b + 0xa
```

So if we just seed our rand the same way, we will get the same guess every time. You can see an example of this in [POC/RandomSeedForGuess.\*](./POC) 

---

The strategy here is the following:
1. Get the guess right using the seeding method mentioned
2. Leak addresses the second time we are asked for our name
3. Overwrite the return address to point back to buf where our shellcode exists from the read vuln

After successfully executing these steps we will have pwn'd the machine.

---

These steps can be seen in the solve script [solve.py](./solve.py)