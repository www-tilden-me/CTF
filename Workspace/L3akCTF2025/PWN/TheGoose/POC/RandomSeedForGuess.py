import os
import time
from ctypes import CDLL

libc = CDLL("libc.so.6")

now = int(time.time())
libc.srand(now)

guess = libc.rand() % 0x5b + 0xa

os.system(f"echo {guess} | ./randtest")
